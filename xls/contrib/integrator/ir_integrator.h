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
// limitations under the License.

#ifndef XLS_INTEGRATOR_IR_INTEGRATOR_H_
#define XLS_INTEGRATOR_IR_INTEGRATOR_H_

#include "absl/status/statusor.h"
#include "xls/ir/function.h"
#include "xls/ir/package.h"

namespace xls {

// Class that represents an integration function i.e. a function combining the
// IR of other functions. This class tracks which orignal function nodes are
// mapped to which integration function nodes. It also provides some utilities
// that are useful for constructing the integrated function.
class IntegrationFunction {
 public:
  IntegrationFunction() {}

  // Create an IntegrationFunction object that is empty expect for
  // paramters.
  static absl::StatusOr<std::unique_ptr<IntegrationFunction>>
  MakeIntegrationFunctionWithParamTuples(
      Package* package, absl::Span<const Function* const> source_functions);

  Function* function() const { return function_.get(); }

  // Declares that node 'source' from a source function maps
  // to node 'map_target' in the integrated_function.
  absl::Status SetNodeMapping(const Node* source, Node* map_target);

  // Returns the integrated node that 'original' maps to, if it
  // exists. Otherwise, return an error status.
  absl::StatusOr<Node*> GetNodeMapping(const Node* original) const;

  // Returns the original nodes that map to 'map_target' in the integrated
  // function.
  absl::StatusOr<const absl::flat_hash_set<const Node*>*> GetNodesMappedToNode(
      const Node* map_target) const;

  // Returns true if 'node' is mapped to a node in the integrated function.
  bool HasMapping(const Node* node) const;

  // Returns true if other nodes map to 'node'
  bool IsMappingTarget(const Node* node) const;

  // Returns true if 'node' is in the integrated function.
  bool IntegrationFunctionOwnsNode(const Node* node) const {
    return function_.get() == node->function();
  }

 private:
  // Track mapping of original function nodes to integrated function nodes.
  absl::flat_hash_map<const Node*, Node*> original_node_to_integrated_node_map_;
  absl::flat_hash_map<const Node*, absl::flat_hash_set<const Node*>>
      integrated_node_to_original_nodes_map_;

  // Integrated function.
  std::unique_ptr<Function> function_;
  Package* package_;
};

// Class used to integrate separate functions into a combined, reprogrammable
// circuit that can be configured to have the same functionality as the
// input functions. The builder will attempt to construct the integrated
// funciton such that hardware common to the input functions is consolidated.
// Note that this is distinct from function inlining. With inlining, a function
// call is replaced by the body of the function that is called.  With function
// integration, we take separate functions that do not call each other and
// combine the hardware used to implement the functions.
class IntegrationBuilder {
 public:
  IntegrationBuilder(absl::Span<const Function* const> input_functions) {
    // TODO(jbaileyhandle): Make package name an optional argument.
    original_package_source_functions_.insert(
        original_package_source_functions_.end(), input_functions.begin(),
        input_functions.end());
  }

  Package* package() { return package_.get(); }
  absl::Span<const Function* const> source_functions() const {
    return source_functions_;
  }

  // Produce an integrated function implementing all
  // all functions in source_functions_.
  absl::StatusOr<Function*> Build();

  // Returns an empty function with a signature that
  // packs source function parameters into separate tuples.
  absl::StatusOr<Function*> GetNewFunctionStub();

 private:
  // Copy the source functions into a common package.
  absl::Status CopySourcesToIntegrationPackage();

  // Common package for to-be integrated functions
  // and integrated function.
  std::unique_ptr<Package> package_;

  // Functions to be integrated, in the integration package.
  std::vector<Function*> source_functions_;
  // Functions to be integrated, in their original packages.
  std::vector<const Function*> original_package_source_functions_;
};

}  // namespace xls

#endif  // XLS_INTEGRATOR_IR_INTEGRATOR_H_
