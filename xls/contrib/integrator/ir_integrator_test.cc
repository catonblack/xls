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

#include "xls/contrib/integrator/ir_integrator.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "xls/common/status/matchers.h"
#include "xls/ir/ir_matcher.h"
#include "xls/ir/ir_parser.h"
#include "xls/ir/ir_test_base.h"
#include "xls/ir/package.h"

namespace m = ::xls::op_matchers;

namespace xls {
namespace {

using status_testing::IsOkAndHolds;
using ::testing::UnorderedElementsAre;

class IntegratorTest : public IrTestBase {};

TEST_F(IntegratorTest, NoSourceFunctions) {
  IntegrationBuilder builder({});
  EXPECT_FALSE(builder.Build().ok());
}

TEST_F(IntegratorTest, OneSourceFunction) {
  std::string program = R"(package dot

fn __dot__add(a: bits[32], b: bits[32]) -> bits[32] {
  ret add.3: bits[32] = add(a, b, id=3, pos=0,1,4)
}

fn ____dot__main_counted_for_0_body(idx: bits[32], acc: bits[32], a: bits[32][3], b: bits[32][3]) -> bits[32] {
  array_index.12: bits[32] = array_index(a, idx, id=12, pos=0,6,16)
  array_index.13: bits[32] = array_index(b, idx, id=13, pos=0,6,25)
  umul.14: bits[32] = umul(array_index.12, array_index.13, id=14, pos=0,6,22)
  ret invoke.15: bits[32] = invoke(acc, umul.14, to_apply=__dot__add, id=15, pos=0,7,7)
}

fn __dot__main(a: bits[32][3], b: bits[32][3]) -> bits[32] {
  literal.6: bits[32] = literal(value=0, id=6, pos=0,8,10)
  literal.7: bits[32] = literal(value=3, id=7, pos=0,5,49)
  ret counted_for.16: bits[32] = counted_for(literal.6, trip_count=3, stride=1, body=____dot__main_counted_for_0_body, invariant_args=[a, b], id=16, pos=0,5,5)
}
)";
  XLS_ASSERT_OK_AND_ASSIGN(auto p, Parser::ParsePackage(program));
  IntegrationBuilder builder({p->EntryFunction().value()});
  XLS_ASSERT_OK_AND_ASSIGN(auto integration_func, builder.Build());

  // Integrated function is just the original entry function.
  EXPECT_EQ(
      integration_func,
      builder.package()->GetFunction("PKGzzzdotzzzFNzzz__dot__main").value());

  auto get_function_names = [](Package* p) {
    std::vector<std::string> names;
    for (const auto& func : p->functions()) {
      names.push_back(func->name());
    }
    return names;
  };

  auto get_called_function_names = [](Package* p) {
    std::vector<std::string> names;
    for (const auto& func : p->functions()) {
      for (const auto* node : func->nodes()) {
        if (node->op() == Op::kCountedFor) {
          names.push_back(node->As<CountedFor>()->body()->name());
        }
        if (node->op() == Op::kInvoke) {
          names.push_back(node->As<Invoke>()->to_apply()->name());
        }
      }
    }
    return names;
  };

  // Original package is unchanged.
  EXPECT_THAT(
      get_function_names(p.get()),
      UnorderedElementsAre("__dot__add", "____dot__main_counted_for_0_body",
                           "__dot__main"));
  EXPECT_THAT(
      get_called_function_names(p.get()),
      UnorderedElementsAre("__dot__add", "____dot__main_counted_for_0_body"));

  // IntegrationBuilder package uses qualified function names (including calls).
  EXPECT_THAT(
      get_function_names(builder.package()),
      UnorderedElementsAre("PKGzzzdotzzzFNzzz__dot__add",
                           "PKGzzzdotzzzFNzzz____dot__main_counted_for_0_body",
                           "PKGzzzdotzzzFNzzz__dot__main"));
  EXPECT_THAT(get_called_function_names(builder.package()),
              UnorderedElementsAre(
                  "PKGzzzdotzzzFNzzz__dot__add",
                  "PKGzzzdotzzzFNzzz____dot__main_counted_for_0_body"));
}

TEST_F(IntegratorTest, MappingTestSimple) {
  auto p = CreatePackage();
  XLS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<IntegrationFunction> integration,
      std::move(IntegrationFunction::MakeIntegrationFunctionWithParamTuples(
          p.get(), {})));
  Function& internal_func = *integration->function();
  Function external_func("external", p.get());

  XLS_ASSERT_OK_AND_ASSIGN(
      Node * internal_1,
      internal_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "internal_1",
                                    p->GetBitsType(1)));
  XLS_ASSERT_OK_AND_ASSIGN(
      Node * external_1,
      external_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "external_1",
                                    p->GetBitsType(2)));

  // Before mapping.
  EXPECT_TRUE(integration->IntegrationFunctionOwnsNode(internal_1));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_1));
  EXPECT_FALSE(integration->HasMapping(internal_1));
  EXPECT_FALSE(integration->HasMapping(external_1));
  EXPECT_FALSE(integration->IsMappingTarget(internal_1));
  EXPECT_FALSE(integration->IsMappingTarget(external_1));
  EXPECT_FALSE(integration->GetNodeMapping(internal_1).ok());
  EXPECT_FALSE(integration->GetNodeMapping(external_1).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(internal_1).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_1).ok());

  // Mapping = external_1 -> MapsTo -> internal_1
  XLS_ASSERT_OK(integration->SetNodeMapping(external_1, internal_1));

  // After mapping.
  EXPECT_TRUE(integration->IntegrationFunctionOwnsNode(internal_1));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_1));
  EXPECT_FALSE(integration->HasMapping(internal_1));
  EXPECT_TRUE(integration->HasMapping(external_1));
  EXPECT_TRUE(integration->IsMappingTarget(internal_1));
  EXPECT_FALSE(integration->IsMappingTarget(external_1));
  EXPECT_FALSE(integration->GetNodeMapping(internal_1).ok());
  ASSERT_THAT(integration->GetNodeMapping(external_1),
              IsOkAndHolds(internal_1));
  auto mapped_to_internal_1 = integration->GetNodesMappedToNode(internal_1);
  EXPECT_TRUE(mapped_to_internal_1.ok());
  EXPECT_THAT(*(mapped_to_internal_1.value()),
              UnorderedElementsAre(external_1));
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_1).ok());
}

TEST_F(IntegratorTest, MappingTestMultipleNodesMapToTarget) {
  auto p = CreatePackage();
  XLS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<IntegrationFunction> integration,
      std::move(IntegrationFunction::MakeIntegrationFunctionWithParamTuples(
          p.get(), {})));
  Function& internal_func = *integration->function();
  Function external_func("external", p.get());

  XLS_ASSERT_OK_AND_ASSIGN(
      Node * internal_1,
      internal_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "internal_1",
                                    p->GetBitsType(1)));
  XLS_ASSERT_OK_AND_ASSIGN(
      Node * external_1,
      external_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "external_1",
                                    p->GetBitsType(2)));
  XLS_ASSERT_OK_AND_ASSIGN(
      Node * external_2,
      external_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "external_1",
                                    p->GetBitsType(3)));

  // Before mapping.
  EXPECT_TRUE(integration->IntegrationFunctionOwnsNode(internal_1));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_1));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_2));
  EXPECT_FALSE(integration->HasMapping(internal_1));
  EXPECT_FALSE(integration->HasMapping(external_1));
  EXPECT_FALSE(integration->HasMapping(external_2));
  EXPECT_FALSE(integration->IsMappingTarget(internal_1));
  EXPECT_FALSE(integration->IsMappingTarget(external_1));
  EXPECT_FALSE(integration->IsMappingTarget(external_2));
  EXPECT_FALSE(integration->GetNodeMapping(internal_1).ok());
  EXPECT_FALSE(integration->GetNodeMapping(external_1).ok());
  EXPECT_FALSE(integration->GetNodeMapping(external_2).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(internal_1).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_1).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_2).ok());

  // Mapping = external_1 && external_2 -> MapsTo -> internal_1
  XLS_ASSERT_OK(integration->SetNodeMapping(external_1, internal_1));
  XLS_ASSERT_OK(integration->SetNodeMapping(external_2, internal_1));

  // After mapping.
  EXPECT_TRUE(integration->IntegrationFunctionOwnsNode(internal_1));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_1));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_2));
  EXPECT_FALSE(integration->HasMapping(internal_1));
  EXPECT_TRUE(integration->HasMapping(external_1));
  EXPECT_TRUE(integration->HasMapping(external_2));
  EXPECT_TRUE(integration->IsMappingTarget(internal_1));
  EXPECT_FALSE(integration->IsMappingTarget(external_1));
  EXPECT_FALSE(integration->IsMappingTarget(external_2));
  EXPECT_FALSE(integration->GetNodeMapping(internal_1).ok());
  ASSERT_THAT(integration->GetNodeMapping(external_1),
              IsOkAndHolds(internal_1));
  ASSERT_THAT(integration->GetNodeMapping(external_2),
              IsOkAndHolds(internal_1));
  auto mapped_to_internal_1 = integration->GetNodesMappedToNode(internal_1);
  EXPECT_TRUE(mapped_to_internal_1.ok());
  EXPECT_THAT(*(mapped_to_internal_1.value()),
              UnorderedElementsAre(external_1, external_2));
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_1).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_2).ok());
}

TEST_F(IntegratorTest, MappingTestRepeatedMapping) {
  auto p = CreatePackage();
  XLS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<IntegrationFunction> integration,
      std::move(IntegrationFunction::MakeIntegrationFunctionWithParamTuples(
          p.get(), {})));
  Function& internal_func = *integration->function();
  Function external_func("external", p.get());

  XLS_ASSERT_OK_AND_ASSIGN(
      Node * internal_1,
      internal_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "internal_1",
                                    p->GetBitsType(1)));
  XLS_ASSERT_OK_AND_ASSIGN(
      Node * internal_2,
      internal_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "internal_2",
                                    p->GetBitsType(2)));
  XLS_ASSERT_OK_AND_ASSIGN(
      Node * external_1,
      external_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "external_1",
                                    p->GetBitsType(3)));
  XLS_ASSERT_OK_AND_ASSIGN(
      Node * external_2,
      external_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "external_2",
                                    p->GetBitsType(4)));

  // Before mapping.
  EXPECT_TRUE(integration->IntegrationFunctionOwnsNode(internal_1));
  EXPECT_TRUE(integration->IntegrationFunctionOwnsNode(internal_2));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_1));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_2));
  EXPECT_FALSE(integration->HasMapping(internal_1));
  EXPECT_FALSE(integration->HasMapping(internal_2));
  EXPECT_FALSE(integration->HasMapping(external_1));
  EXPECT_FALSE(integration->HasMapping(external_2));
  EXPECT_FALSE(integration->IsMappingTarget(internal_1));
  EXPECT_FALSE(integration->IsMappingTarget(internal_2));
  EXPECT_FALSE(integration->IsMappingTarget(external_1));
  EXPECT_FALSE(integration->IsMappingTarget(external_2));
  EXPECT_FALSE(integration->GetNodeMapping(internal_1).ok());
  EXPECT_FALSE(integration->GetNodeMapping(internal_2).ok());
  EXPECT_FALSE(integration->GetNodeMapping(external_1).ok());
  EXPECT_FALSE(integration->GetNodeMapping(external_2).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(internal_1).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(internal_2).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_1).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_2).ok());

  // Mapping = external_1 && external_2 -> MapsTo -> internal_1
  XLS_ASSERT_OK(integration->SetNodeMapping(external_1, internal_1));
  XLS_ASSERT_OK(integration->SetNodeMapping(external_2, internal_1));

  // Mapping = external_1 && external_2 -> MapsTo -> internal_1 -> internal_2
  XLS_ASSERT_OK(integration->SetNodeMapping(internal_1, internal_2));

  // After mapping.
  EXPECT_TRUE(integration->IntegrationFunctionOwnsNode(internal_1));
  EXPECT_TRUE(integration->IntegrationFunctionOwnsNode(internal_2));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_1));
  EXPECT_FALSE(integration->IntegrationFunctionOwnsNode(external_2));
  EXPECT_FALSE(integration->HasMapping(internal_1));
  EXPECT_FALSE(integration->HasMapping(internal_2));
  EXPECT_TRUE(integration->HasMapping(external_1));
  EXPECT_TRUE(integration->HasMapping(external_2));
  EXPECT_FALSE(integration->IsMappingTarget(internal_1));
  EXPECT_TRUE(integration->IsMappingTarget(internal_2));
  EXPECT_FALSE(integration->IsMappingTarget(external_1));
  EXPECT_FALSE(integration->IsMappingTarget(external_2));
  EXPECT_FALSE(integration->GetNodeMapping(internal_1).ok());
  EXPECT_FALSE(integration->GetNodeMapping(internal_2).ok());
  ASSERT_THAT(integration->GetNodeMapping(external_1),
              IsOkAndHolds(internal_2));
  ASSERT_THAT(integration->GetNodeMapping(external_2),
              IsOkAndHolds(internal_2));
  EXPECT_FALSE(integration->GetNodesMappedToNode(internal_1).ok());
  auto mapped_to_internal_2 = integration->GetNodesMappedToNode(internal_2);
  EXPECT_TRUE(mapped_to_internal_2.ok());
  EXPECT_THAT(*(mapped_to_internal_2.value()),
              UnorderedElementsAre(external_1, external_2));
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_1).ok());
  EXPECT_FALSE(integration->GetNodesMappedToNode(external_2).ok());
}

TEST_F(IntegratorTest, MappingTestSetNodeMappingFailureCases) {
  auto p = CreatePackage();
  XLS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<IntegrationFunction> integration,
      std::move(IntegrationFunction::MakeIntegrationFunctionWithParamTuples(
          p.get(), {})));
  Function& internal_func = *integration->function();
  Function external_func("external", p.get());

  XLS_ASSERT_OK_AND_ASSIGN(
      Node * internal_1,
      internal_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "internal_1",
                                    p->GetBitsType(1)));
  XLS_ASSERT_OK_AND_ASSIGN(
      Node * internal_2,
      internal_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "internal_2",
                                    p->GetBitsType(2)));
  XLS_ASSERT_OK_AND_ASSIGN(
      Node * external_1,
      external_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "external_1",
                                    p->GetBitsType(3)));
  XLS_ASSERT_OK_AND_ASSIGN(
      Node * external_2,
      external_func.MakeNodeWithName<Param>(/*loc=*/std::nullopt, "external_2",
                                    p->GetBitsType(4)));

  // Mapping = external_1 -> MapsTo -> external_1
  // Mapping target must be internal.
  EXPECT_FALSE(integration->SetNodeMapping(external_1, external_1).ok());

  // Mapping = external_1 -> MapsTo -> external_2
  // Mapping target must be internal.
  EXPECT_FALSE(integration->SetNodeMapping(external_1, external_2).ok());

  // Mapping = internal_1 -> MapsTo -> external_1
  // Mapping target must be internal.
  EXPECT_FALSE(integration->SetNodeMapping(internal_1, external_1).ok());

  // Mapping = internal_1 -> MapsTo -> internal_1
  // Cannot map to self.
  EXPECT_FALSE(integration->SetNodeMapping(internal_1, internal_1).ok());

  // Mapping = internal_2 -> MapsTo -> internal_1
  // Cannot map internal nodes that are not mapping targets.
  EXPECT_FALSE(integration->SetNodeMapping(internal_2, internal_1).ok());
}

TEST_F(IntegratorTest, ParamterPacking) {
  auto p = CreatePackage();
  FunctionBuilder fb_a("func_a", p.get());
  fb_a.Param("a1", p->GetBitsType(2));
  fb_a.Param("a2", p->GetBitsType(4));
  XLS_ASSERT_OK_AND_ASSIGN(Function * func_a, fb_a.Build());

  FunctionBuilder fb_b("func_b", p.get());
  fb_b.Param("b1", p->GetBitsType(6));
  fb_b.Param("b2", p->GetBitsType(8));
  XLS_ASSERT_OK_AND_ASSIGN(Function * func_b, fb_b.Build());

  XLS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<IntegrationFunction> integration,
      std::move(IntegrationFunction::MakeIntegrationFunctionWithParamTuples(
          p.get(), {func_a, func_b})));

  auto GetTupleIndexWithNumBits = [&](long int num_bits) {
    for (Node* node : integration->function()->nodes()) {
      if (node->op() == Op::kTupleIndex) {
        if (node->GetType() == p->GetBitsType(num_bits)) {
          return absl::optional<Node*>(node);
        }
      }
    }
    return absl::optional<Node*>(std::nullopt);
  };
  auto GetParamWithNumBits = [&p](Function* function, long int num_bits) {
    for (Node* node : function->nodes()) {
      if (node->op() == Op::kParam) {
        if (node->GetType() == p->GetBitsType(num_bits)) {
          return absl::optional<Node*>(node);
        }
      }
    }
    return absl::optional<Node*>(std::nullopt);
  };

  auto a1_index = GetTupleIndexWithNumBits(2);
  EXPECT_TRUE(a1_index.has_value());
  EXPECT_TRUE(a1_index.has_value());
  EXPECT_THAT(a1_index.value(), m::TupleIndex(m::Param("func_aParamTuple"), 0));
  auto a1_source = GetParamWithNumBits(func_a, 2);
  EXPECT_TRUE(a1_source.has_value());
  EXPECT_TRUE(integration->HasMapping(a1_source.value()));
  EXPECT_EQ(integration->GetNodeMapping(a1_source.value()).value(),
            a1_index.value());
  EXPECT_TRUE(integration->IsMappingTarget(a1_index.value()));
  EXPECT_THAT(*(integration->GetNodesMappedToNode(a1_index.value()).value()),
              UnorderedElementsAre(a1_source.value()));

  auto a2_index = GetTupleIndexWithNumBits(4);
  EXPECT_TRUE(a2_index.has_value());
  EXPECT_THAT(a2_index.value(), m::TupleIndex(m::Param("func_aParamTuple"), 1));
  ;
  auto a2_source = GetParamWithNumBits(func_a, 4);
  EXPECT_TRUE(a2_source.has_value());
  EXPECT_TRUE(integration->HasMapping(a2_source.value()));
  EXPECT_EQ(integration->GetNodeMapping(a2_source.value()).value(),
            a2_index.value());
  EXPECT_TRUE(integration->IsMappingTarget(a2_index.value()));
  EXPECT_THAT(*(integration->GetNodesMappedToNode(a2_index.value()).value()),
              UnorderedElementsAre(a2_source.value()));

  auto b1_index = GetTupleIndexWithNumBits(6);
  EXPECT_TRUE(b1_index.has_value());
  EXPECT_THAT(b1_index.value(), m::TupleIndex(m::Param("func_bParamTuple"), 0));
  ;
  auto b1_source = GetParamWithNumBits(func_b, 6);
  EXPECT_TRUE(b1_source.has_value());
  EXPECT_TRUE(integration->HasMapping(b1_source.value()));
  EXPECT_EQ(integration->GetNodeMapping(b1_source.value()).value(),
            b1_index.value());
  EXPECT_TRUE(integration->IsMappingTarget(b1_index.value()));
  EXPECT_THAT(*(integration->GetNodesMappedToNode(b1_index.value()).value()),
              UnorderedElementsAre(b1_source.value()));

  auto b2_index = GetTupleIndexWithNumBits(8);
  EXPECT_TRUE(b2_index.has_value());
  EXPECT_THAT(b2_index.value(), m::TupleIndex(m::Param("func_bParamTuple"), 1));
  ;
  auto b2_source = GetParamWithNumBits(func_b, 8);
  EXPECT_TRUE(b2_source.has_value());
  EXPECT_TRUE(integration->HasMapping(b2_source.value()));
  EXPECT_EQ(integration->GetNodeMapping(b2_source.value()).value(),
            b2_index.value());
  EXPECT_TRUE(integration->IsMappingTarget(b2_index.value()));
  EXPECT_THAT(*(integration->GetNodesMappedToNode(b2_index.value()).value()),
              UnorderedElementsAre(b2_source.value()));

  EXPECT_EQ(integration->function()->node_count(), 6);
}

}  // namespace
}  // namespace xls
