# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_rust//rust:defs.bzl", "rust_proc_macro")
load("//third_party/cargo:crates.bzl", "all_crate_deps")

package(default_visibility = ["//visibility:public"])

rust_proc_macro(
    name = "opentitantool_derive",
    srcs = ["src/lib.rs"],
    deps = [] + all_crate_deps(),
)
