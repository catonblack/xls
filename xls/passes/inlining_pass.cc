// Copyright 2020 The XLS Authors
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

#include "xls/passes/inlining_pass.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "xls/common/status/status_macros.h"
#include "xls/ir/node_iterator.h"

namespace xls {
namespace {

bool ShouldInline(Invoke* invoke) {
  // Inline all the things!
  //
  // TODO(xls-team): 2019-04-12 May want a more sophisticated policy than this
  // one day.
  return true;
}

// Finds an "effectively used" (has users or is return value) invoke in the
// function f, or returns nullptr if none is found.
Invoke* FindInvoke(FunctionBase* f) {
  for (Node* node : TopoSort(f)) {
    if (node->Is<Invoke>() &&
        (node == f->return_value() || !node->users().empty()) &&
        ShouldInline(node->As<Invoke>())) {
      return node->As<Invoke>();
    }
  }
  return nullptr;
}

// Return the name that 'node' should have when it is inlined at the callsite
// given by 'invoke'. The node must be in the function called by 'invoke'. The
// name is generated by first determining if the name of 'node' is likely
// derived from the parameter name of its function. If so, a new name is
// generated using the respective operand name of 'invoke' substituted for the
// parameter name. If no meaningful name could be determined then nullopt is
// returned.
absl::optional<std::string> GetInlinedNodeName(Node* node, Invoke* invoke) {
  if (!node->HasAssignedName()) {
    return absl::nullopt;
  }

  // Find the parameter in the invoked function whose name is a prefix of the
  // name of 'node'. If such a parameter exists we assume the name of 'node' is
  // derived from the name of this param. If there are multiple matches, then
  // choose the param with the longest name (e.g., if the node's name is
  // 'foo_bar_42' and there are parameters named 'foo' and 'foo_bar' we assume
  // 'foo_bar_42' is derived from 'foo_bar').
  Param* matching_param = nullptr;
  std::string derived_name;
  for (int64 i = 0; i < invoke->operand_count(); ++i) {
    Param* param = invoke->to_apply()->param(i);
    Node* operand = invoke->operand(i);
    if (operand->HasAssignedName() &&
        absl::StartsWith(node->GetName(), param->GetName()) &&
        (matching_param == nullptr ||
         matching_param->GetName().size() < param->GetName().size())) {
      matching_param = param;
      std::string suffix = node->GetName().substr(param->GetName().size());
      derived_name = absl::StrCat(operand->GetName(), suffix);
    }
  }
  if (matching_param == nullptr) {
    return absl::nullopt;
  }
  return derived_name;
}

// Inlines the node "invoke" by replacing it with the contents of the called
// function.
absl::Status InlineInvoke(Invoke* invoke) {
  Function* invoked = invoke->to_apply();
  absl::flat_hash_map<Node*, Node*> invoked_node_to_replacement;
  for (int64 i = 0; i < invoked->params().size(); ++i) {
    Node* param = invoked->param(i);
    invoked_node_to_replacement[param] = invoke->operand(i);
  }

  for (Node* node : TopoSort(invoked)) {
    if (invoked_node_to_replacement.contains(node)) {
      // Already taken care of (e.g. parameters above).
      continue;
    }
    std::vector<Node*> new_operands;
    for (Node* operand : node->operands()) {
      new_operands.push_back(invoked_node_to_replacement.at(operand));
    }
    XLS_ASSIGN_OR_RETURN(
        Node * new_node,
        node->CloneInNewFunction(new_operands, invoke->function()));
    invoked_node_to_replacement[node] = new_node;
  }

  // Generate meaningful names for each of the newly inlined nodes. For example,
  // if the callsite looks like:
  //
  //   invoke.1: invoke(foo, to_apply=f)
  //
  // and the function is:
  //
  //   fn f(x: bits[32]) -> bits[32] {
  //     ...
  //     x_negated: bits[32] = neg(x)
  //     ...
  //   }
  //
  // Then 'x_negated' when inlined at the invoke callsite will have the name
  // 'foo_negated'.
  for (Node* node : invoked->nodes()) {
    if (node->Is<Param>()) {
      continue;
    }
    if (node == invoked->return_value() && invoke->HasAssignedName()) {
      // Node is the return value of the function, it should get its name from
      // the invoke node itself. By clearing the name here ReplaceUseWith will
      // properly move the name from the invoke instruction to the node.
      invoked_node_to_replacement.at(node)->ClearName();
      continue;
    }
    absl::optional<std::string> new_name = GetInlinedNodeName(node, invoke);
    if (new_name.has_value()) {
      invoked_node_to_replacement.at(node)->SetName(new_name.value());
    }
  }

  XLS_RETURN_IF_ERROR(invoke
                          ->ReplaceUsesWith(invoked_node_to_replacement.at(
                              invoked->return_value()))
                          .status());
  return invoke->function()->RemoveNode(invoke);
}

}  // namespace

absl::StatusOr<bool> InliningPass::RunOnFunctionBase(
    FunctionBase* f, const PassOptions& options, PassResults* results) const {
  bool changed = false;
  while (true) {
    Invoke* invoke = FindInvoke(f);
    if (invoke == nullptr) {
      break;
    }
    XLS_RETURN_IF_ERROR(InlineInvoke(invoke));
    changed = true;
  }
  return changed;
}

}  // namespace xls
