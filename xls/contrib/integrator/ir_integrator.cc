// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License

#include "xls/contrib/integrator/ir_integrator.h"

#include "xls/ir/ir_parser.h"

namespace xls {

absl::StatusOr<std::unique_ptr<IntegrationFunction>>
IntegrationFunction::MakeIntegrationFunctionWithParamTuples(
    Package* package, absl::Span<const Function* const> source_functions) {
  // Create integration function object.
  std::unique_ptr<IntegrationFunction> integration_function =
      absl::make_unique<IntegrationFunction>();
  integration_function->package_ = package;

  // Create ir function.
  // TODO(jbaileyhandle): Make function name an optional argument.
  static int64 integration_functions_count = 0;
  std::string function_name = std::string("IntegrationFunction") +
                              std::to_string(integration_functions_count++);
  integration_function->function_ =
      absl::make_unique<Function>(function_name, package);

  // Package source function parameters as tuple parameters to integration
  // function.
  for (const auto* source_func : source_functions) {
    // Add tuple paramter for source function.
    std::vector<Type*> arg_types;
    for (const Node* param : source_func->params()) {
      arg_types.push_back(param->GetType());
    }
    Type* args_tuple_type = package->GetTupleType(arg_types);
    std::string tuple_name = source_func->name() + std::string("ParamTuple");
    XLS_ASSIGN_OR_RETURN(
        Node * args_tuple,
        integration_function->function_->MakeNode<Param>(
            /*loc=*/std::nullopt, tuple_name, args_tuple_type));

    // Add TupleIndex nodes inside function to unpack tuple parameter.
    int64 paramter_index = 0;
    for (const Node* param : source_func->params()) {
      XLS_ASSIGN_OR_RETURN(
          Node * tuple_index,
          integration_function->function_->MakeNode<TupleIndex>(
              /*loc=*/std::nullopt, args_tuple, paramter_index));
      XLS_RETURN_IF_ERROR(
          integration_function->SetNodeMapping(param, tuple_index));
      paramter_index++;
    }
  }

  return std::move(integration_function);
}

absl::Status IntegrationFunction::SetNodeMapping(const Node* source,
                                                 Node* map_target) {
  // Validate map pairing.
  if (source == map_target) {
    return absl::InternalError("Tried to map a node to itself");
  }
  if (!IntegrationFunctionOwnsNode(map_target)) {
    return absl::InternalError(
        "Tried to map to a node not owned by the integration function");
  }
  // TODO(jbaileyhandle): Reasonable assumption for short-term use cases.  May
  // be worth relaxing to enable some optimizations of some sort?
  if (IntegrationFunctionOwnsNode(source) && !IsMappingTarget(source)) {
    return absl::InternalError(
        "Tried to map an integration function node that is not itself a "
        "mapping target");
  }

  // 'original' is itself a member of the integrated function.
  if (IntegrationFunctionOwnsNode(source)) {
    absl::flat_hash_set<const Node*>& nodes_that_map_to_source =
        integrated_node_to_original_nodes_map_.at(source);

    // Nodes that previously mapped to original now map to map_target.
    for (const Node* original_node : nodes_that_map_to_source) {
      integrated_node_to_original_nodes_map_[map_target].insert(original_node);
      XLS_RET_CHECK(HasMapping(original_node));
      original_node_to_integrated_node_map_[original_node] = map_target;
    }

    // No nodes map to source anymore.
    integrated_node_to_original_nodes_map_.erase(source);

    // 'source' is an external node.
  } else {
    original_node_to_integrated_node_map_[source] = map_target;
    integrated_node_to_original_nodes_map_[map_target].insert(source);
  }

  return absl::OkStatus();
}

absl::StatusOr<Node*> IntegrationFunction::GetNodeMapping(
    const Node* original) const {
  XLS_RET_CHECK(!IntegrationFunctionOwnsNode(original));
  if (!HasMapping(original)) {
    return absl::InternalError("No mapping found for original node");
  }
  return original_node_to_integrated_node_map_.at(original);
}

absl::StatusOr<const absl::flat_hash_set<const Node*>*>
IntegrationFunction::GetNodesMappedToNode(const Node* map_target) const {
  XLS_RET_CHECK(IntegrationFunctionOwnsNode(map_target));
  if (!IsMappingTarget(map_target)) {
    return absl::InternalError("No mappings found for map target node");
  }
  return &integrated_node_to_original_nodes_map_.at(map_target);
}

bool IntegrationFunction::HasMapping(const Node* node) const {
  return original_node_to_integrated_node_map_.contains(node);
}

bool IntegrationFunction::IsMappingTarget(const Node* node) const {
  return integrated_node_to_original_nodes_map_.find(node) !=
         integrated_node_to_original_nodes_map_.end();
}

// Return the name of 'function', prepended with the 'package' name.
std::string GetParsableQualifiedFunctionName(Package* package,
                                             const Function* function) {
  return "PKGzzz" + package->name() + "zzzFNzzz" + function->name();
}

absl::Status IntegrationBuilder::CopySourcesToIntegrationPackage() {
  std::string integration_package_str = "package IntegrationPackage\n";

  // Dump IR for original functions with qualified names.
  for (const auto* source : original_package_source_functions_) {
    // Copy functions to temporary package to avoid modifying
    // original functions.
    std::string srctmp_package_str = "package srctmp\n";
    srctmp_package_str.append(source->DumpIr(/*recursive=*/true));
    XLS_ASSIGN_OR_RETURN(auto srctmp_package,
                         Parser::ParsePackage(srctmp_package_str));

    // Change all function names before dumping any function so that
    // all function invocations refer to the new function name.
    for (const auto& function : srctmp_package->functions()) {
      function->SetName(
          GetParsableQualifiedFunctionName(source->package(), function.get()));
    }

    // Dump functions to common IR string.
    for (const auto& function : srctmp_package->functions()) {
      integration_package_str.append("\n");
      integration_package_str.append(function->DumpIr(/*recursive=*/false));
    }
  }

  // Parse funtions into common package.
  XLS_ASSIGN_OR_RETURN(package_, Parser::ParsePackage(integration_package_str));
  source_functions_.reserve(original_package_source_functions_.size());
  for (const auto* source : original_package_source_functions_) {
    XLS_ASSIGN_OR_RETURN(Function * new_func,
                         package_->GetFunction(GetParsableQualifiedFunctionName(
                             source->package(), source)));
    source_functions_.push_back(new_func);
  }

  return absl::OkStatus();
}

absl::StatusOr<Function*> IntegrationBuilder::Build() {
  // Add sources to common package.
  XLS_RETURN_IF_ERROR(CopySourcesToIntegrationPackage());

  switch (source_functions_.size()) {
    case 0:
      return absl::InternalError(
          "No source functions provided for integration");
    case 1:
      return source_functions_.front();
    default:
      return absl::InternalError("Integration not yet implemented.");
      break;
  }
}

}  // namespace xls
