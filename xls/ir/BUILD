# Copyright 2020 The XLS Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Compiler data structures for converting high level algorithms into Hardware
# Description Language.

load("@xls_pip_deps//:requirements.bzl", "requirement")
load("@bazel_skylib//rules:build_test.bzl", "build_test")

# cc_proto_library is used in this file
load("//xls/build:py_proto_library.bzl", "xls_py_proto_library")
# pytype library only

package(
    default_visibility = ["//xls:xls_internal"],
    licenses = ["notice"],  # Apache 2.0
)

cc_library(
    name = "bit_push_buffer",
    hdrs = ["bit_push_buffer.h"],
    deps = [
        "//xls/common:integral_types",
        "//xls/common:math_util",
    ],
)

cc_test(
    name = "bit_push_buffer_test",
    srcs = ["bit_push_buffer_test.cc"],
    deps = [
        ":bit_push_buffer",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "bits",
    srcs = ["bits.cc"],
    hdrs = ["bits.h"],
    deps = [
        ":bit_push_buffer",
        ":format_preference",
        "//xls/common:bits_util",
        "//xls/common:integral_types",
        "//xls/common:math_util",
        "//xls/common/logging",
        "//xls/data_structures:inline_bitmap",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "ternary",
    srcs = ["ternary.cc"],
    hdrs = ["ternary.h"],
    deps = [
        ":bits",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "bits_test",
    size = "small",
    srcs = [
        "bits_test.cc",
    ],
    deps = [
        ":bits",
        ":number_parser",
        ":value",
        "//xls/common:math_util",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "type",
    srcs = ["type.cc"],
    hdrs = ["type.h"],
    deps = [
        ":xls_type_cc_proto",
        "//xls/common:casts",
        "//xls/common:integral_types",
        "//xls/common/logging",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "op",
    srcs = ["op.cc"],
    hdrs = ["op.h"],
    deps = [
        ":op_cc_proto",
        "//xls/common:integral_types",
        "//xls/common/logging",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:span",
    ],
)

cc_proto_library(
    name = "op_cc_proto",
    deps = [":op_proto"],
)

proto_library(
    name = "op_proto",
    srcs = ["op.proto"],
)

xls_py_proto_library(
    name = "op_py_pb2",
    srcs = ["op.proto"],
    internal_deps = [":op_proto"],
)

cc_library(
    name = "ir",
    srcs = [
        "container_hack.inc",
        "container_hack_undef.inc",
        "dfs_visitor.cc",
        "function.cc",
        "function_base.cc",
        "node.cc",
        "node_iterator.cc",
        "nodes.cc",
        "package.cc",
        "proc.cc",
        "verifier.cc",
    ],
    hdrs = [
        "dfs_visitor.h",
        "function.h",
        "function_base.h",
        "lsb_or_msb.h",
        "node.h",
        "node_iterator.h",
        "nodes.h",
        "package.h",
        "proc.h",
        "verifier.h",
    ],
    deps = [
        ":bits",
        ":channel",
        ":channel_cc_proto",
        ":name_uniquer",
        ":op",
        ":source_location",
        ":type",
        ":unwrapping_iterator",
        ":value",
        "//xls/common:casts",
        "//xls/common:integral_types",
        "//xls/common:iterator_range",
        "//xls/common:math_util",
        "//xls/common:strong_int",
        "//xls/common/logging",
        "//xls/common/logging:log_lines",
        "//xls/common/status:ret_check",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/container:inlined_vector",
        "@com_google_absl//absl/container:node_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:span",
    ],
)

cc_test(
    name = "node_iterator_test",
    srcs = ["node_iterator_test.cc"],
    deps = [
        ":ir",
        ":ir_parser",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "function_builder",
    srcs = ["function_builder.cc"],
    hdrs = ["function_builder.h"],
    deps = [
        ":ir",
        ":source_location",
        ":value",
        "//xls/common:symbolized_stacktrace",
        "//xls/common/logging",
        "//xls/common/status:ret_check",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "function_builder_test",
    srcs = ["function_builder_test.cc"],
    deps = [
        ":function_builder",
        ":ir",
        ":ir_matcher",
        "//xls/common/status:matchers",
        "//xls/examples:sample_packages",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "source_location",
    hdrs = [
        "fileno.h",
        "source_location.h",
    ],
    deps = [
        "//xls/common:integral_types",
        "//xls/common:strong_int",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
    ],
)

cc_library(
    name = "ir_scanner",
    srcs = ["ir_scanner.cc"],
    hdrs = ["ir_scanner.h"],
    deps = [
        ":bits",
        ":number_parser",
        "//xls/common:integral_types",
        "//xls/common/logging",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "ir_scanner_test",
    srcs = ["ir_scanner_test.cc"],
    deps = [
        ":ir_scanner",
        "//xls/common/status:matchers",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "ir_parser",
    srcs = ["ir_parser.cc"],
    hdrs = ["ir_parser.h"],
    deps = [
        ":bits_ops",
        ":channel",
        ":channel_cc_proto",
        ":function_builder",
        ":ir",
        ":ir_scanner",
        ":number_parser",
        ":op",
        ":source_location",
        ":type",
        "//xls/common:visitor",
        "//xls/common/logging",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "ir_parser_test",
    size = "small",
    srcs = ["ir_parser_test.cc"],
    deps = [
        "ir_parser",
        ":bits_ops",
        ":number_parser",
        "//xls/common:source_location",
        "//xls/common/status:matchers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "package_test",
    size = "small",
    srcs = ["package_test.cc"],
    deps = [
        "ir",
        ":ir_test_base",
        ":type",
        ":xls_type_cc_proto",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "node_util_test",
    size = "small",
    srcs = ["node_util_test.cc"],
    deps = [
        ":function_builder",
        ":ir",
        ":ir_matcher",
        ":ir_test_base",
        ":node_util",
        ":op",
        "//xls/common/status:matchers",
        "//xls/common/status:ret_check",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "ir_test_base",
    testonly = True,
    srcs = ["ir_test_base.cc"],
    hdrs = ["ir_test_base.h"],
    deps = [
        ":ir",
        ":ir_parser",
        ":value_test_util",
        "//xls/codegen:combinational_generator",
        "//xls/codegen:module_signature",
        "//xls/common:source_location",
        "//xls/common/logging",
        "//xls/common/status:matchers",
        "//xls/common/status:ret_check",
        "//xls/common/status:status_macros",
        "//xls/delay_model:delay_estimator",
        "//xls/delay_model:delay_estimators",
        "//xls/interpreter:ir_interpreter",
        "//xls/passes:standard_pipeline",
        "//xls/scheduling:pipeline_schedule",
        "//xls/simulation:module_simulator",
        "//xls/simulation:verilog_simulators",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "dfs_visitor_test",
    srcs = ["dfs_visitor_test.cc"],
    deps = [
        ":ir",
        ":ir_test_base",
        "//xls/common/logging",
        "//xls/common/status:matchers",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "verifier_test",
    srcs = ["verifier_test.cc"],
    deps = [
        ":ir",
        ":ir_test_base",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "value",
    srcs = ["value.cc"],
    hdrs = ["value.h"],
    deps = [
        ":bits",
        ":xls_type_cc_proto",
        "//xls/common/logging",
        "//xls/common/status:ret_check",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@com_google_absl//absl/types:variant",
        "@com_google_re2//:re2",
    ],
)

cc_library(
    name = "value_helpers",
    srcs = ["value_helpers.cc"],
    hdrs = ["value_helpers.h"],
    deps = [
        ":ir",
        ":type",
        ":value",
        "//xls/common/logging",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "value_test",
    srcs = ["value_test.cc"],
    deps = [
        ":bits",
        ":ir",
        ":value",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "node_test",
    srcs = ["node_test.cc"],
    deps = [
        ":function_builder",
        ":ir",
        ":ir_test_base",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "function_test",
    srcs = ["function_test.cc"],
    deps = [
        ":function_builder",
        ":ir",
        ":ir_test_base",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ir_test_base_test",
    srcs = ["ir_test_base_test.cc"],
    deps = [
        ":ir_test_base",
        "//xls/common/status:matchers",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "value_test_util_test",
    srcs = ["value_test_util_test.cc"],
    deps = [
        ":value",
        ":value_test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "type_test",
    srcs = ["type_test.cc"],
    deps = [
        ":function_builder",
        ":ir",
        ":type",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "format_preference",
    srcs = ["format_preference.cc"],
    hdrs = ["format_preference.h"],
    deps = [
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "value_test_util",
    testonly = True,
    srcs = ["value_test_util.cc"],
    hdrs = ["value_test_util.h"],
    deps = [
        ":value",
        "@com_google_googletest//:gtest",
    ],
)

filegroup(
    name = "templates",
    srcs = glob(["*.tmpl"]),
)

# op_specification is very slow to type check so don't use a type checking
# target. Types are checked separately in the build test
# op_specification_build_test.
py_binary(
    name = "render_specification_against_template",
    srcs = [
        "op_specification.py",
        "render_specification_against_template.py",
    ],
    data = [
        ":templates",
    ],
    python_version = "PY3",
    deps = [
        requirement("Jinja2"),
        requirement("MarkupSafe"),
        "//xls/common:runfiles",
        "@com_google_absl_py//absl:app",
    ],
)

py_library(
    name = "op_specification_typechecked",
    srcs = [
        "op_specification.py",
    ],
    srcs_version = "PY2AND3",
)

build_test(
    name = "op_specification_build_test",
    targets = ["op_specification_typechecked"],
)

genrule(
    name = "op_header",
    outs = ["op.h"],
    cmd = "$(location :render_specification_against_template) xls/ir/op_header.tmpl" +
          " | $(location @llvm_toolchain//:bin/clang-format)" +
          " > $(OUTS)",
    exec_tools = [
        ":render_specification_against_template",
        "@llvm_toolchain//:bin/clang-format",
    ],
)

genrule(
    name = "gen_op_proto",
    outs = ["op.proto"],
    cmd = "$(location :render_specification_against_template) xls/ir/op_proto.tmpl > $(OUTS)",
    exec_tools = [
        ":render_specification_against_template",
        "@llvm_toolchain//:bin/clang-format",
    ],
)

genrule(
    name = "op_source",
    outs = ["op.cc"],
    cmd = "$(location :render_specification_against_template) xls/ir/op_source.tmpl" +
          " | $(location @llvm_toolchain//:bin/clang-format)" +
          " > $(OUTS)",
    exec_tools = [
        ":render_specification_against_template",
        "@llvm_toolchain//:bin/clang-format",
    ],
)

genrule(
    name = "nodes_header",
    outs = ["nodes.h"],
    cmd = "$(location :render_specification_against_template) xls/ir/nodes_header.tmpl" +
          " | $(location @llvm_toolchain//:bin/clang-format)" +
          " > $(OUTS)",
    exec_tools = [
        ":render_specification_against_template",
        "@llvm_toolchain//:bin/clang-format",
    ],
)

genrule(
    name = "nodes_source",
    outs = ["nodes.cc"],
    cmd = "$(location :render_specification_against_template) xls/ir/nodes_source.tmpl" +
          " | $(location @llvm_toolchain//:bin/clang-format)" +
          " > $(OUTS)",
    exec_tools = [
        ":render_specification_against_template",
        "@llvm_toolchain//:bin/clang-format",
    ],
)

cc_library(
    name = "number_parser",
    srcs = ["number_parser.cc"],
    hdrs = ["number_parser.h"],
    deps = [
        ":bits",
        ":bits_ops",
        ":format_preference",
        "//xls/common:integral_types",
        "//xls/common/status:ret_check",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "bits_ops",
    srcs = ["bits_ops.cc"],
    hdrs = ["bits_ops.h"],
    deps = [
        ":big_int",
        ":bits",
        ":op",
        "//xls/common/logging",
    ],
)

cc_library(
    name = "node_util",
    srcs = ["node_util.cc"],
    hdrs = ["node_util.h"],
    deps = [
        ":bits_ops",
        ":ir",
        "//xls/common/logging",
        "//xls/common/status:ret_check",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/functional:function_ref",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "big_int",
    srcs = ["big_int.cc"],
    hdrs = ["big_int.h"],
    deps = [
        ":bits",
        "//xls/common/logging",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "number_parser_test",
    srcs = ["number_parser_test.cc"],
    deps = [
        ":bits_ops",
        ":number_parser",
        "//xls/common:integral_types",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "big_int_test",
    srcs = ["big_int_test.cc"],
    deps = [
        ":big_int",
        ":bits",
        ":number_parser",
        "//xls/common/status:matchers",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "bits_ops_test",
    srcs = ["bits_ops_test.cc"],
    deps = [
        ":bits_ops",
        ":number_parser",
        ":value",
        "//xls/common:math_util",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

proto_library(
    name = "xls_type_proto",
    srcs = ["xls_type.proto"],
)

cc_proto_library(
    name = "xls_type_cc_proto",
    deps = [":xls_type_proto"],
)

xls_py_proto_library(
    name = "xls_type_py_pb2",
    srcs = ["xls_type.proto"],
    internal_deps = [":xls_type_proto"],
)

proto_library(
    name = "channel_proto",
    srcs = ["channel.proto"],
)

cc_proto_library(
    name = "channel_cc_proto",
    deps = [":channel_proto"],
)

xls_py_proto_library(
    name = "channel_py_pb2",
    srcs = ["channel.proto"],
    internal_deps = [
        ":channel_proto",
    ],
)

cc_library(
    name = "keyword_args",
    srcs = ["keyword_args.cc"],
    hdrs = ["keyword_args.h"],
    deps = [
        ":ir",
        ":value",
        "//xls/common/logging",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "unwrapping_iterator",
    hdrs = ["unwrapping_iterator.h"],
)

cc_library(
    name = "ir_matcher",
    testonly = True,
    srcs = ["ir_matcher.cc"],
    hdrs = ["ir_matcher.h"],
    deps = [
        ":format_preference",
        ":ir",
        ":ir_parser",
        ":op",
        ":type",
        ":value",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "abstract_evaluator",
    hdrs = ["abstract_evaluator.h"],
    deps = [
        ":bits",
        "//xls/common:integral_types",
        "//xls/common/logging",
        "@com_google_absl//absl/functional:function_ref",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "abstract_node_evaluator",
    hdrs = ["abstract_node_evaluator.h"],
    deps = [
        ":ir",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/types:optional",
    ],
)

cc_library(
    name = "value_view",
    hdrs = ["value_view.h"],
    deps = [
        ":ir",
        ":type",
        "//xls/common:bits_util",
        "//xls/common:integral_types",
        "//xls/common:math_util",
        "//xls/common/logging",
    ],
)

cc_library(
    name = "value_view_helpers",
    hdrs = ["value_view_helpers.h"],
    deps = [
        ":value_view",
        "@com_google_absl//absl/base",
    ],
)

cc_library(
    name = "channel",
    srcs = ["channel.cc"],
    hdrs = ["channel.h"],
    deps = [
        ":channel_cc_proto",
        ":type",
        "//xls/common:integral_types",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "name_uniquer",
    srcs = ["name_uniquer.cc"],
    hdrs = ["name_uniquer.h"],
    deps = [
        "//xls/common:integral_types",
        "//xls/common/logging",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "value_view_test",
    srcs = ["value_view_test.cc"],
    deps = [
        ":bits",
        ":bits_ops",
        ":value_helpers",
        ":value_view",
        "//xls/common:bits_util",
        "//xls/common:integral_types",
        "//xls/common:math_util",
        "//xls/common/status:matchers",
        "//xls/common/status:ret_check",
        "//xls/common/status:status_macros",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "abstract_evaluator_test",
    srcs = ["abstract_evaluator_test.cc"],
    deps = [
        ":abstract_evaluator",
        ":bits",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ir_matcher_test",
    srcs = ["ir_matcher_test.cc"],
    deps = [
        ":bits",
        ":function_builder",
        ":ir",
        ":ir_matcher",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "value_helpers_test",
    srcs = ["value_helpers_test.cc"],
    deps = [
        ":bits_ops",
        ":ir",
        ":value",
        ":value_helpers",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "proc_test",
    srcs = ["proc_test.cc"],
    deps = [
        ":ir",
        ":ir_matcher",
        ":ir_test_base",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "channel_test",
    srcs = ["channel_test.cc"],
    deps = [
        ":channel",
        ":ir",
        ":ir_parser",
        "//xls/common/status:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "name_uniquer_test",
    srcs = ["name_uniquer_test.cc"],
    deps = [
        ":name_uniquer",
        "@com_google_googletest//:gtest_main",
    ],
)
