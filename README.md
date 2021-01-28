# VMill

VMill is a snapshot-based process emulator. It just-in-time lifts machine code to LLVM bitcode, and enables that bitcodet to be instrumented. That bitcode is then compiled to machine code and executed.

## Getting Help

If you are experiencing undocumented problems with Remill then ask for help in the `#binary-lifting` channel of the [Empire Hacking Slack](https://empireslacking.herokuapp.com/).

## Supported Platforms

Remill is supported on Linux platforms and has been tested on debian testing.

## Dependencies

Most of vmill's dependencies can be provided by the [cxx-common](https://github.com/trailofbits/cxx-common) repository. Trail of Bits hosts downloadable, pre-built versions of cxx-common, which makes it substantially easier to get up and running with vmill. Nonetheless, the following table represents most of vmill's dependencies.

| Name | Version |
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 3.14+ |
| [Google Flags](https://github.com/google/glog) | Latest |
| [Google Log](https://github.com/google/glog) | Latest |
| [LLVM](http://llvm.org/) | 3.5+ |
| [Clang](http://clang.llvm.org/) | 3.5+ |
| [Intel XED](https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library) | Latest |
| [remill](https://github.com/lifting-bits/remill) | 4.0.13 |
| C++ compiler | C++17 |

## Getting and Building the Code

First, update aptitude and get install the baseline dependencies such is for example `git`, `cmake` and your compiler of choice (remember it needs to support C++17). It is useful to use the same compiler at every subset to avoid some name mangling problems.

### cxx-common

As for the dependencies, most of them are provided by [cxx-common](https://github.com/trailofbits/cxx-common). To get them you have two options:
  * Get the pre-built package for some available architectures
  * Build the yourself. (Can take around 40 minutes, since LLVM is being built)
For more depth on each option consult `README` of the project.

If you choose to build it manually first get the sources:
```shell
# Clone
git clone https://github.com/trailofbits/cxx-common.git
cd cxx-common
```

The repository uses [vcpkg](https://github.com/microsoft/vcpkg) which makes entire process rather easy.
```shell
./build_dependencies --release llvm-9
```
If you plan to tinker with the project rather than use, drop the `--release` so you get the debug build
of LLVM. It is important *do not forget the llvm-9* option, otherwise it will not build and subsequently
the projects built in next step will try to link system libraries and that is highly unstable and not
tested (at least for now).

### Remill

Once `cxx-common` is build, you have everything needed to build Remill.
Remill provides some prebuilt Dockers, however the manual build is also an option:
```shell
git clone https://github.com/lifting-bits/remill.git
cd remill
mkdir build
cd build
cmake -DVCPKG_ROOT=/path/to/cxx-common/vcpkg -DCMAKE_INSTALL_PREFIX=path/to/install ..
make install
```
You can optionally use the `scripts/build.sh`.

### vmill

And finally to vmill itself.
```
git clone https://github.com/lifting-bits/vmill.git
cd vmill
mkdir build
cd build
cmake -DVCPKG_ROOT=/path/to/cxx-common/vcpkg -DCMAKE_INSTALL_PREFIX=path/to/install -Dremill_DIR=path/to/remill/install/dir/lib/cmake/remill ..
make install
```
