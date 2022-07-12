# F.O Bachelor Thesis


## Requirements
It is recommended a debian based system like Ubuntu or Kali for simulating OpenTitan. Moreover, python 3.10 does
not work with
fusesoc, so you will need to downgrade to 3.9 or lower.
## Setting up the system

First off, you will need to set up the system, so follow these steps:
* cd / && mkdir tools && cd tools
* git clone https://github.com/florylsk/opentitanTFG
* export REPO_TOP=/tools/opentitanTFG (add this to .zshrc or equivalent)
* sudo apt install autoconf bison build-essential clang-format cmake curl \
  doxygen flex g++ git golang lcov libelf1 libelf-dev libftdi1-2 \
  libftdi1-dev libncurses5 libssl-dev libudev-dev libusb-1.0-0 lsb-release \
  make ninja-build perl pkgconf python3 python3-pip python3-setuptools \
  python3-urllib3 python3-wheel srecord tree xsltproc zlib1g-dev xz-utils
* pip3 install --user -r python-requirements.txt
* ./util/get-toolchain.py
* export VERILATOR_VERSION=4.210
* cd /tools && git clone https://github.com/verilator/verilator.git
* cd verilator
* git checkout v$VERILATOR_VERSION
* autoconf
* ./configure --prefix=/tools/verilator/$VERILATOR_VERSION
* make
* make install
* export PATH=/tools/verilator/$VERILATOR_VERSION/bin:$PATH (add this to .zshrc or equivalent)
* cd $REPO_TOP && ci/scripts/build-chip-verilator.sh earlgrey
* ./meson_init.sh
* ninja -C build-out all

This all will set up the base system and will only be done once unless you want to change the system. In case you do,
after modifying files in `/hw` you will need to rebuild the simulation with fusesoc like
`ci/scripts/build-chip-verilator.sh earlgrey`. In case you modify files in `/sw`, you only need to call
`ninja -C build-out all`

Now you can start the simulation at any time with
```console
$ build-bin/hw/top_earlgrey/Vchip_earlgrey_verilator \
--meminit=rom,build-bin/sw/device/lib/testing/test_rom/test_rom_sim_verilator.scr.39.vmem \
--meminit=flash,build-bin/sw/device/examples/hello_world/hello_world_sim_verilator.64.scr.vmem \
--meminit=otp,build-bin/sw/device/otp_img/otp_img_sim_verilator.vmem
```

## Setting up PoWha
Proof of Walk Human attestation is based on ZoKrates, so you will need it (only 0.4.9 version is tested).
Follow these steps to set it up:
* cd /tmp
* wget "https://github.com/Zokrates/ZoKrates/releases/download/0.4.9/zokrates-0.4.9-x86_64-unknown-linux-gnu.tar.gz"
* tar -xvf "zokrates-0.4.9-x86_64-unknown-linux-gnu.tar.gz"
* mkdir $HOME/.zokrates
* mkdir $HOME/.zokrates/bin
* cp -r stdlib $HOME/.zokrates/
* mv zokrates $HOME/.zokrates/bin/
* export ZOKRATES_HOME="$HOME/.zokrates/stdlib"
* export PATH="$HOME/.zokrates/bin:$PATH"

Strongly recommend adding last 2 exports to your .zshrc or equivalent.

Now you will need to install python requirements with `pip install -r requirements.txt` inside proof-of-walk folder.
Note that geohash library is broken in python3, to fix it simply open `$HOME/.local/lib/yourpythonversion/site-packages/Geohash/__init__.py`
and add a dot before geohash like `from .geohash import decode_exactly, decode, encode`.

## Using PoWha
Now that we have a base system, follow these steps for every route you want to test. Note that you will need 4 TTYs for this
so use tmux, konsole, etc to split the screen.
* Go to Google Maps and select a walking route.
* Go to [mapstogpx](https://mapstogpx.com/) and export the route as GPX
* Go to [mygeodata](https://mygeodata.cloud/converter/gpx-to-csv) and convert the GPX to CSV
* Copy the CSV to `proof_of_walk` with `track_points.csv` file name.
* Start the simulation as explained in TTY1
* Connect with screen to UART in TTY2 (read simulation's stdout to know which pts device to connect to)
* When "GPIO Module is now Functional" message comes up, cd into `proof_of_walk` and execute `device_to_powha.py` twice (first time will flush
  the pipe) in TTY3
* cd into `proof_of_walk` and Execute `sensor_simulator.py test.csv`, changing test.csv for your path data, and
  select Geohash Sensor Simulator in TTY4
