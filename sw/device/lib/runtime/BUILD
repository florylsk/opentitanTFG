# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

package(default_visibility = ["//visibility:public"])

load("//rules:opentitan.bzl", "OPENTITAN_CPU")

cc_library(
    name = "epmp",
    srcs = ["epmp.c"],
    hdrs = ["epmp.h"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        "//sw/device/lib/base/freestanding",
    ],
)

cc_library(
    name = "hart",
    srcs = ["hart.c"],
    hdrs = ["hart.h"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        ":ibex",
        "//sw/device/lib/arch:device",
        "//sw/device/lib/base",
        "//sw/device/lib/base/freestanding",
    ],
)

cc_library(
    name = "ibex",
    srcs = ["ibex.c"],
    hdrs = ["ibex.h"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        "//sw/device/lib/arch:device",
        "//sw/device/lib/base",
    ],
)

cc_library(
    name = "log",
    srcs = ["log.c"],
    hdrs = ["log.h"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        "//sw/device/lib/arch:device",
        "//sw/device/lib/base",
        "//sw/device/lib/base/freestanding",
        "//sw/device/lib/runtime:print",
    ],
)

cc_library(
    name = "otbn",
    srcs = ["otbn.c"],
    hdrs = ["otbn.h"],
    deps = [
        ":log",
        "//sw/device/lib/dif:otbn",
    ],
)

cc_library(
    name = "pmp",
    srcs = ["pmp.c"],
    hdrs = ["pmp.h"],
    target_compatible_with = [OPENTITAN_CPU],
    textual_hdrs = ["pmp_regions.def"],
    deps = [
        "//sw/device/lib/base",
        "//sw/device/lib/base/freestanding",
    ],
)

cc_library(
    name = "print",
    srcs = ["print.c"],
    hdrs = ["print.h"],
    deps = [
        "//sw/device/lib/base",
        "//sw/device/lib/dif:uart",
    ],
)

cc_test(
    name = "print_unittest",
    srcs = ["print_unittest.cc"],
    deps = [
        ":print",
        "//sw/device/lib/base/testing",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)
