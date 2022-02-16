---
title: "FPGA Reference Manual"
---

This manual provides additional usage details about the FPGA.
Specifically, it provides instructions on SW development flows and testing procedures.


## Usage Options

There are two ways to use OpenTitan on the FPGA.
- The first is to build the design from scratch using Vivado.
  Refer to the [Getting Started FPGA]({{< relref "doc/ug/getting_started_fpga" >}}) guide for more information.
- The second is to program the FPGA with a released bitfile using storage devices.
  Refer to the [Quickstart Guide]({{< relref "doc/ug/quickstart" >}}) guide for instructions on this approach.

## FPGA SW Development Flow

The FPGA is meant for both boot ROM and general software development.
The flow for each is different, as the boot ROM is meant to be fairly static while general software can change very frequently.

### Boot ROM development

The FPGA bitstream is built after compiling whatever code is sitting in `sw/device/lib/testing/test_rom`.
This binary is used to initialize internal FPGA memory and is part of the bitstream directly.

To update this content without rebuilding the FPGA, a flow is required to splice a new boot ROM binary into the bitstream.
There are two prerequisites in order for this flow to work:
* The boot ROM during the build process must be correctly inferred by the tool.
  * See [prim_rom](https://github.com/lowRISC/opentitan/blob/master/hw/ip/prim_generic/rtl/prim_generic_rom.sv) and [vivado_hook_opt_design_post.tcl](https://github.com/lowRISC/opentitan/blob/master/hw/top_earlgrey/util/vivado_hook_opt_design_post.tcl).
* The MMI file outlining the physical boot ROM placement and mapping to FPGA block RAM primitives needs to be generated by the tool.
  * See [vivado_hook_write_bitstream_pre.tcl](https://github.com/lowRISC/opentitan/blob/master/hw/top_earlgrey/util/vivado_hook_write_bitstream_pre.tcl).

With these steps in place, a script can be invoked to take a new binary and push its contents into an existing bitfile.
For details, please see the [`splice_rom.sh`](https://github.com/lowRISC/opentitan/blob/master/util/fpga/splice_rom.sh) script.

See example below:

```console
$ cd $REPO_TOP
$ ./util/fpga/splice_rom.sh
$ ./util/fpga/cw310_loader.py --bitstream build/lowrisc_systems_chip_earlgrey_cw310_0.1/synth-vivado/lowrisc_systems_chip_earlgrey_cw310_0.1.bit
```

The script assumes that there is an existing bitfile `build/lowrisc_systems_chip_earlgrey_cw310_0.1/synth-vivado/lowrisc_systems_chip_earlgrey_cw310_0.1.bit` (this is created after following the steps in [getting_started_fpga]({{< relref "doc/ug/getting_started_fpga" >}})).

The script assumes that there is an existing boot ROM image under `build-bin/sw/device/lib/testing/test_rom` and then creates a new bitfile of the same name at the same location.
The original input bitfile is moved to `build/lowrisc_systems_chip_earlgrey_cw310_0.1/synth-vivado/lowrisc_systems_chip_earlgrey_cw310_0.1.bit.orig`.

The `cw310_loader.py` can then be used to directly flash the updated bitstream to the FPGA.

### General Software Development

After building, the FPGA bitstream contains only the boot ROM.
Using this boot ROM, the FPGA is able to load additional software to the emulated flash, such as software in the `sw/device/benchmark`, `sw/device/examples` and `sw/device/tests` directories.
To load additional software, the `cw310_loader.py` is required.

Also the binary you wish to load needs to be built first.
For the purpose of this demonstration, we will use `sw/device/examples/hello_world`, but it applies to any software image that is able to fit in the emulated flash space.
The example below builds the `hello_world` image and loads it onto the FPGA.
The loading output is also shown.

```console
$ cd ${REPO_TOP}
$ ./meson_init.sh
$ ninja -C build-out sw/device/examples/hello_world/hello_world_export_fpga_cw310
$ ./util/fpga/cw310_loader.py --firmware build-bin/sw/device/examples/hello_world/hello_world_fpga_cw310.bin

CW310 Loader: Attemping to find CW310 FPGA Board:
    No bitstream specified
CW310 Board Found:
INFO: Programming firmware file: build-bin/sw/device/examples/hello_world/hello_world_fpga_cw310.bin
Programming OpenTitan with "build-bin/sw/device/examples/hello_world/hello_world_fpga_cw310.bin"...
Transferring frame 0x00000000 @             0x00000000.
Transferring frame 0x00000001 @             0x000007D8.
Transferring frame 0x00000002 @             0x00000FB0.
Transferring frame 0x00000003 @             0x00001788.
Transferring frame 0x00000004 @             0x00001F60.
Transferring frame 0x00000005 @             0x00002738.
Transferring frame 0x80000006 @             0x00002F10.
Loading done.
```

For more details on the exact operation of the loading flow and how the boot ROM processes incoming data, please refer to the [boot ROM readme]({{< relref "sw/device/lib/testing/test_rom/README.md" >}}).