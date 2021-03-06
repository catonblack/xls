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

#include "xls/common/math_util.h"

#include <limits>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace xls {
namespace {

// Number of arguments for each test of the CeilOrRatio method
const int kNumTestArguments = 4;

template <typename IntegralType>
void TestCeilOfRatio(const IntegralType test_data[][kNumTestArguments],
                     int num_tests) {
  for (int i = 0; i < num_tests; ++i) {
    const IntegralType numerator = test_data[i][0];
    const IntegralType denominator = test_data[i][1];
    const IntegralType expected_floor = test_data[i][2];
    const IntegralType expected_ceil = test_data[i][3];
    // Make sure the two ways to compute the floor return the same thing.
    IntegralType floor_1 = FloorOfRatio(numerator, denominator);
    IntegralType floor_2 =
        CeilOrFloorOfRatio<IntegralType, false>(numerator, denominator);
    EXPECT_EQ(floor_1, floor_2);
    EXPECT_EQ(expected_floor, floor_1)
        << "FloorOfRatio fails with numerator = " << numerator
        << ", denominator = " << denominator
        << (std::numeric_limits<IntegralType>::is_signed ? "signed "
                                                         : "unsigned ")
        << (8 * sizeof(IntegralType)) << " bits";
    IntegralType ceil_1 = CeilOfRatio(numerator, denominator);
    IntegralType ceil_2 =
        CeilOrFloorOfRatio<IntegralType, true>(numerator, denominator);
    EXPECT_EQ(ceil_1, ceil_2);
    EXPECT_EQ(expected_ceil, ceil_1)
        << "CeilOfRatio fails with numerator = " << numerator
        << ", denominator = " << denominator
        << (std::numeric_limits<IntegralType>::is_signed ? "signed "
                                                         : "unsigned ")
        << (8 * sizeof(IntegralType)) << " bits";
  }
}

template <typename UnsignedIntegralType>
void TestCeilOfRatioUnsigned() {
  typedef std::numeric_limits<UnsignedIntegralType> Limits;
  EXPECT_TRUE(Limits::is_integer);
  EXPECT_FALSE(Limits::is_signed);
  const UnsignedIntegralType kMax = Limits::max();
  const UnsignedIntegralType kTestData[][kNumTestArguments] = {
      // Numerator  | Denominator | Expected floor of ratio | Expected ceil of
      // ratio |
      // When numerator = 0, the result is always zero
      {0, 1, 0, 0},
      {0, 2, 0, 0},
      {0, kMax, 0, 0},
      // Try some non-extreme cases
      {1, 1, 1, 1},
      {5, 2, 2, 3},
      // Try with huge positive numerator
      {kMax, 1, kMax, kMax},
      {kMax, 2, kMax / 2, kMax / 2 + ((kMax % 2 != 0) ? 1 : 0)},
      {kMax, 3, kMax / 3, kMax / 3 + ((kMax % 3 != 0) ? 1 : 0)},
      // Try with a huge positive denominator
      {1, kMax, 0, 1},
      {2, kMax, 0, 1},
      {3, kMax, 0, 1},
      // Try with a huge numerator and a huge denominator
      {kMax, kMax, 1, 1},
  };
  const int kNumTests = ABSL_ARRAYSIZE(kTestData);
  TestCeilOfRatio<UnsignedIntegralType>(kTestData, kNumTests);
}

template <typename SignedInteger>
void TestCeilOfRatioSigned() {
  typedef std::numeric_limits<SignedInteger> Limits;
  EXPECT_TRUE(Limits::is_integer);
  EXPECT_TRUE(Limits::is_signed);
  const SignedInteger kMin = Limits::min();
  const SignedInteger kMax = Limits::max();
  const SignedInteger kTestData[][kNumTestArguments] = {
      // Numerator  | Denominator | Expected floor of ratio | Expected ceil of
      // ratio |
      // When numerator = 0, the result is always zero
      {0, 1, 0, 0},
      {0, -1, 0, 0},
      {0, 2, 0, 0},
      {0, kMin, 0, 0},
      {0, kMax, 0, 0},
      // Try all four combinations of 1 and -1
      {1, 1, 1, 1},
      {-1, 1, -1, -1},
      {1, -1, -1, -1},
      {-1, -1, 1, 1},
      // Try all four combinations of +/-5 divided by +/- 2
      {5, 2, 2, 3},
      {-5, 2, -3, -2},
      {5, -2, -3, -2},
      {-5, -2, 2, 3},
      // Try with huge positive numerator
      {kMax, 1, kMax, kMax},
      {kMax, -1, -kMax, -kMax},
      {kMax, 2, kMax / 2, kMax / 2 + ((kMax % 2 != 0) ? 1 : 0)},
      {kMax, 3, kMax / 3, kMax / 3 + ((kMax % 3 != 0) ? 1 : 0)},
      // Try with huge negative numerator
      {kMin, 1, kMin, kMin},
      {kMin, 2, kMin / 2 - ((kMin % 2 != 0) ? 1 : 0), kMin / 2},
      {kMin, 3, kMin / 3 - ((kMin % 3 != 0) ? 1 : 0), kMin / 3},
      // Try with a huge positive denominator
      {1, kMax, 0, 1},
      {2, kMax, 0, 1},
      {3, kMax, 0, 1},
      // Try with a huge negative denominator
      {1, kMin, -1, 0},
      {2, kMin, -1, 0},
      {3, kMin, -1, 0},
      // Try with a huge numerator and a huge denominator
      {kMin, kMin, 1, 1},
      {kMin, kMax, -2, -1},
      {kMax, kMin, -1, 0},
      {kMax, kMax, 1, 1},
  };
  const int kNumTests = ABSL_ARRAYSIZE(kTestData);
  TestCeilOfRatio<SignedInteger>(kTestData, kNumTests);
}

// An implementation of CeilOfRatio that is correct for small enough values,
// and provided that the numerator and denominator are both positive
template <typename IntegralType>
IntegralType CeilOfRatioDenomMinusOne(IntegralType numerator,
                                      IntegralType denominator) {
  const IntegralType kOne(1);
  return (numerator + denominator - kOne) / denominator;
}

void TestThatCeilOfRatioDenomMinusOneIsIncorrect(int64 numerator,
                                                 int64 denominator,
                                                 int64 expected_error) {
  const int64 correct_result = CeilOfRatio(numerator, denominator);
  const int64 result_by_denom_minus_one =
      CeilOfRatioDenomMinusOne(numerator, denominator);
  EXPECT_EQ(result_by_denom_minus_one + expected_error, correct_result)
      << "numerator = " << numerator << " denominator = " << denominator
      << " expected error = " << expected_error
      << " Actual difference: " << (correct_result - result_by_denom_minus_one);
}

TEST(MathUtil, CeilOfRatioUint8) { TestCeilOfRatioUnsigned<uint8>(); }

TEST(MathUtil, CeilOfRatioUint16) { TestCeilOfRatioUnsigned<uint16>(); }

TEST(MathUtil, CeilOfRatioUint32) { TestCeilOfRatioUnsigned<uint32>(); }

TEST(MathUtil, CeilOfRatioUint64) { TestCeilOfRatioUnsigned<uint64>(); }

TEST(MathUtil, CeilOfRatioInt8) { TestCeilOfRatioSigned<int8>(); }

TEST(MathUtil, CeilOfRatioInt16) { TestCeilOfRatioSigned<int16>(); }

TEST(MathUtil, CeilOfRatioInt32) { TestCeilOfRatioSigned<int32>(); }

TEST(MathUtil, CeilOfRatioInt64) { TestCeilOfRatioSigned<int64>(); }

TEST(MathUtil, CeilOfRatioDenomMinusOneIsIncorrect) {
  // Here we demonstrate why not to use CeilOfRatioDenomMinusOne: It does not
  // work with negative values.
  TestThatCeilOfRatioDenomMinusOneIsIncorrect(-1LL, -2LL, -1LL);

  // This would also fail if given kint64max because of signed integer overflow.
}

TEST(MathUtil, CeilOfLog2) {
  EXPECT_EQ(CeilOfLog2(0), 0);
  EXPECT_EQ(CeilOfLog2(1), 0);
  EXPECT_EQ(CeilOfLog2(2), 1);
  EXPECT_EQ(CeilOfLog2(3), 2);
  EXPECT_EQ(CeilOfLog2(4), 2);
  EXPECT_EQ(CeilOfLog2(5), 3);
  EXPECT_EQ(CeilOfLog2((1ULL << 63) - 1ULL), 63);
  EXPECT_EQ(CeilOfLog2(1ULL << 63), 63);
  EXPECT_EQ(CeilOfLog2((1ULL << 63) + 1ULL), 64);
  EXPECT_EQ(CeilOfLog2(std::numeric_limits<uint64>::max()), 64);
}

TEST(MathUtil, FloorOfLog2) {
  EXPECT_EQ(FloorOfLog2(0), 0);
  EXPECT_EQ(FloorOfLog2(1), 0);
  EXPECT_EQ(FloorOfLog2(2), 1);
  EXPECT_EQ(FloorOfLog2(3), 1);
  EXPECT_EQ(FloorOfLog2(4), 2);
  EXPECT_EQ(FloorOfLog2(5), 2);
  EXPECT_EQ(FloorOfLog2((1ULL << 63) - 1ULL), 62);
  EXPECT_EQ(FloorOfLog2(1ULL << 63), 63);
  EXPECT_EQ(FloorOfLog2((1ULL << 63) + 1ULL), 63);
  EXPECT_EQ(FloorOfLog2(std::numeric_limits<uint64>::max()), 63);
}

}  // namespace
}  // namespace xls
