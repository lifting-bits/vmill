# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

project(vmill)
cmake_minimum_required (VERSION 3.2)

find_package(ZLIB REQUIRED)

set(VMILL_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
set(VMILL_TOOLS_DIR "${PROJECT_SOURCE_DIR}/tools")

list(APPEND PROJECT_INCLUDEDIRECTORIES "${VMILL_SOURCE_DIR}")
list(APPEND PROJECT_INCLUDEDIRECTORIES "${VMILL_TOOLS_DIR}")

list(APPEND PROJECT_DEFINITIONS "VMILL_INSTALL_RUNTIME_DIR=\"${CMAKE_INSTALL_PREFIX}/share/vmill/${REMILL_LLVM_VERSION}/runtime/\"")
list(APPEND PROJECT_DEFINITIONS "VMILL_BUILD_RUNTIME_DIR=\"${CMAKE_CURRENT_BINARY_DIR}/vmill/Runtime/\"")

# protobuf
find_package(Protobuf REQUIRED)
list(APPEND PROJECT_LIBRARIES ${Protobuf_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${Protobuf_INCLUDE_DIR})
list(APPEND PROJECT_DEFINITIONS "GOOGLE_PROTOBUF_NO_RTTI")

#
# protobuf file generation 
#

# this function can't be told where to store the output files! we have to add the whole binary directory
# to the include directories (or change it and lose compatibility with the system libraries)
protobuf_generate_cpp(PROJECT_PROTOBUFSOURCEFILES PROJECT_PROTOBUFHEADERFILES
                      "${CMAKE_CURRENT_SOURCE_DIR}/vmill/Program/Snapshot.proto")
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_CURRENT_BINARY_DIR})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${PROJECT_PROTOBUFHEADERFILES})

# disable -Werror on these file since they have been generated
set_source_files_properties(${PROJECT_PROTOBUFSOURCEFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion")
set_source_files_properties(${PROJECT_PROTOBUFHEADERFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion")

add_library(${PROJECT_NAME} STATIC
    ${PROJECT_PROTOBUFSOURCEFILES}
    vmill/Arch/Decoder.cpp
    vmill/Arch/Arch.cpp
    vmill/Arch/X86/Log.cpp
    vmill/Arch/X86/Coroutine.S
    vmill/Arch/X86/Runtime.S
    vmill/Arch/X86/Signal.S
    vmill/Arch/AArch64/Log.cpp
    
    vmill/BC/Compiler.cpp
    vmill/BC/Lifter.cpp
    vmill/BC/Optimize.cpp
    vmill/BC/Util.cpp
    
    vmill/Executor/AsyncIO.cpp
    vmill/Executor/CodeCache.cpp
    vmill/Executor/Coroutine.cpp
    vmill/Executor/Executor.cpp
    vmill/Executor/Memory.cpp
    vmill/Executor/Runtime.cpp
    
    vmill/Program/AddressSpace.cpp
    vmill/Program/MappedRange.cpp
    vmill/Program/ShadowMemory.cpp
    vmill/Program/Snapshot.cpp
    
    vmill/Util/AreaAllocator.cpp
    vmill/Util/Hash.cpp
    vmill/Util/Timer.cpp
    vmill/Util/Util.cpp
    vmill/Util/ZoneAllocator.cpp
    
    vmill/Workspace/Tool.cpp
    vmill/Workspace/Workspace.cpp
    
    tools/Fuzzer/Location.cpp
    tools/Fuzzer/BranchCoverage.cpp
    tools/Fuzzer/ValueCoverage.cpp
    tools/Fuzzer/Fuzzer.cpp

    tools/TaintTracker/TaintTracker.cpp
    tools/TaintTracker/DataFlowTracker.cpp
    
    tools/KVM/KVM.cpp
    
    third_party/liballoc/liballoc.c
    third_party/ThreadPool/ThreadPool.cpp
    third_party/xxHash/xxhash.c
)

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)

# add everything as public.
target_link_libraries(${PROJECT_NAME} PUBLIC remill ${ZLIB_LIBRARIES} LLVMCodeGen LLVMAsmPrinter LLVMRuntimeDyld LLVMExecutionEngine LLVMTarget LLVMX86AsmParser LLVMX86AsmPrinter LLVMX86CodeGen LLVMAArch64AsmParser LLVMAArch64AsmPrinter LLVMAArch64CodeGen)
target_include_directories(${PROJECT_NAME} PUBLIC SYSTEM ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

set(VMILL_INCLUDEDIRECTORIES ${PROJECT_INCLUDEDIRECTORIES})

add_subdirectory(vmill/Runtime)

set(VMILL_EXECUTE vmill-execute-${REMILL_LLVM_VERSION})

add_executable(${VMILL_EXECUTE}
    Execute.cpp
)

target_link_libraries(${VMILL_EXECUTE} PRIVATE vmill ${PROJECT_LIBRARIES})
target_include_directories(${VMILL_EXECUTE} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${VMILL_EXECUTE} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${VMILL_EXECUTE} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

install(
    TARGETS ${VMILL_EXECUTE}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

if (UNIX AND NOT APPLE)
    set(VMILL_KVM vmill-kvm-${REMILL_LLVM_VERSION})
    
    add_executable(${VMILL_KVM}
        Virtualize.cpp
    )
    
    target_link_libraries(${VMILL_KVM} PRIVATE vmill ${PROJECT_LIBRARIES}
        /lib/x86_64-linux-gnu/libseccomp.so.2
/usr/lib/x86_64-linux-gnu/libSDL-1.2.so.0
/usr/lib/x86_64-linux-gnu/libX11.so.6
/lib/x86_64-linux-gnu/libbrlapi.so.0.6
/usr/lib/x86_64-linux-gnu/libcacard.so.0
/usr/lib/x86_64-linux-gnu/libusbredirparser.so.1
/lib/x86_64-linux-gnu/libusb-1.0.so.0
/lib/x86_64-linux-gnu/libz.so.1
/lib/x86_64-linux-gnu/libaio.so.1
/usr/lib/x86_64-linux-gnu/libiscsi.so.2
/usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4
/usr/lib/x86_64-linux-gnu/librbd.so.1
/usr/lib/x86_64-linux-gnu/librados.so.2
/usr/lib/x86_64-linux-gnu/libpixman-1.so.0
/lib/x86_64-linux-gnu/libutil.so.1
/usr/lib/x86_64-linux-gnu/libnuma.so.1
/usr/lib/x86_64-linux-gnu/libbluetooth.so.3
/lib/x86_64-linux-gnu/libpng12.so.0
/usr/lib/x86_64-linux-gnu/libjpeg.so.8
/usr/lib/x86_64-linux-gnu/libsasl2.so.2
/usr/lib/x86_64-linux-gnu/libnettle.so.6
/usr/lib/x86_64-linux-gnu/libgnutls.so.30
/usr/lib/x86_64-linux-gnu/libxenstore.so.3.0
/usr/lib/x86_64-linux-gnu/libxenctrl-4.6.so
/usr/lib/x86_64-linux-gnu/libxenguest-4.6.so
/usr/lib/x86_64-linux-gnu/libspice-server.so.1
/lib/x86_64-linux-gnu/libm.so.6
/lib/x86_64-linux-gnu/libpthread.so.0
/usr/lib/x86_64-linux-gnu/libgthread-2.0.so.0
/lib/x86_64-linux-gnu/libglib-2.0.so.0
/lib/x86_64-linux-gnu/librt.so.1
/usr/lib/x86_64-linux-gnu/libstdc++.so.6
/lib/x86_64-linux-gnu/libgcc_s.so.1
/lib/x86_64-linux-gnu/libc.so.6
/usr/lib/x86_64-linux-gnu/libasound.so.2
/lib/x86_64-linux-gnu/libdl.so.2
/usr/lib/x86_64-linux-gnu/libpulse-simple.so.0
/usr/lib/x86_64-linux-gnu/libpulse.so.0
/usr/lib/x86_64-linux-gnu/libXext.so.6
/usr/lib/x86_64-linux-gnu/libcaca.so.0
/usr/lib/x86_64-linux-gnu/libxcb.so.1
/usr/lib/x86_64-linux-gnu/libnss3.so
/usr/lib/x86_64-linux-gnu/libnspr4.so
/lib/x86_64-linux-gnu/libudev.so.1
/usr/lib/x86_64-linux-gnu/libidn.so.11
/usr/lib/x86_64-linux-gnu/librtmp.so.1
/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2
/usr/lib/x86_64-linux-gnu/liblber-2.4.so.2
/usr/lib/x86_64-linux-gnu/libldap_r-2.4.so.2
/usr/lib/x86_64-linux-gnu/libboost_thread.so.1.58.0
/usr/lib/x86_64-linux-gnu/libboost_random.so.1.58.0
/lib/x86_64-linux-gnu/libblkid.so.1
/usr/lib/x86_64-linux-gnu/libboost_iostreams.so.1.58.0
/usr/lib/x86_64-linux-gnu/libboost_system.so.1.58.0
/usr/lib/x86_64-linux-gnu/libsmime3.so
/usr/lib/x86_64-linux-gnu/libp11-kit.so.0
/usr/lib/x86_64-linux-gnu/libtasn1.so.6
/usr/lib/x86_64-linux-gnu/libhogweed.so.4
/usr/lib/x86_64-linux-gnu/libgmp.so.10
/lib/x86_64-linux-gnu/liblzma.so.5
/usr/lib/x86_64-linux-gnu/libopus.so.0
/lib/x86_64-linux-gnu/libssl.so.1.0.0
/lib/x86_64-linux-gnu/libcrypto.so.1.0.0
/lib/x86_64-linux-gnu/libpcre.so.3
/usr/lib/x86_64-linux-gnu/pulseaudio/libpulsecommon-8.0.so
/lib/x86_64-linux-gnu/libjson-c.so.2
/lib/x86_64-linux-gnu/libdbus-1.so.3
/lib/x86_64-linux-gnu/libslang.so.2
/lib/x86_64-linux-gnu/libncursesw.so.5
/lib/x86_64-linux-gnu/libtinfo.so.5
/usr/lib/x86_64-linux-gnu/libXau.so.6
/usr/lib/x86_64-linux-gnu/libXdmcp.so.6
/usr/lib/x86_64-linux-gnu/libnssutil3.so
/usr/lib/x86_64-linux-gnu/libplc4.so
/usr/lib/x86_64-linux-gnu/libplds4.so
/usr/lib/x86_64-linux-gnu/libkrb5.so.3
/usr/lib/x86_64-linux-gnu/libk5crypto.so.3
/lib/x86_64-linux-gnu/libcom_err.so.2
/usr/lib/x86_64-linux-gnu/libkrb5support.so.0
/lib/x86_64-linux-gnu/libresolv.so.2
/usr/lib/x86_64-linux-gnu/libgssapi.so.3
/lib/x86_64-linux-gnu/libuuid.so.1
/lib/x86_64-linux-gnu/libbz2.so.1.0
/usr/lib/x86_64-linux-gnu/libffi.so.6
/lib/x86_64-linux-gnu/libsystemd.so.0
/lib/x86_64-linux-gnu/libwrap.so.0
/usr/lib/x86_64-linux-gnu/libsndfile.so.1
/usr/lib/x86_64-linux-gnu/libasyncns.so.0
/lib/x86_64-linux-gnu/libkeyutils.so.1
/usr/lib/x86_64-linux-gnu/libheimntlm.so.0
/usr/lib/x86_64-linux-gnu/libkrb5.so.26
/usr/lib/x86_64-linux-gnu/libasn1.so.8
/usr/lib/x86_64-linux-gnu/libhcrypto.so.4
/usr/lib/x86_64-linux-gnu/libroken.so.18
/lib/x86_64-linux-gnu/libselinux.so.1
/lib/x86_64-linux-gnu/libgcrypt.so.20
/lib/x86_64-linux-gnu/libnsl.so.1
/usr/lib/x86_64-linux-gnu/libFLAC.so.8
/usr/lib/x86_64-linux-gnu/libvorbisenc.so.2
/usr/lib/x86_64-linux-gnu/libwind.so.0
/usr/lib/x86_64-linux-gnu/libheimbase.so.1
/usr/lib/x86_64-linux-gnu/libhx509.so.5
/usr/lib/x86_64-linux-gnu/libsqlite3.so.0
/lib/x86_64-linux-gnu/libcrypt.so.1
/lib/x86_64-linux-gnu/libgpg-error.so.0
/usr/lib/x86_64-linux-gnu/libogg.so.0
/usr/lib/x86_64-linux-gnu/libvorbis.so.0)
    target_include_directories(${VMILL_KVM} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
    target_compile_definitions(${VMILL_KVM} PUBLIC ${PROJECT_DEFINITIONS})
    set_target_properties(${VMILL_KVM} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})
    
    install(
        TARGETS ${VMILL_KVM}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
    )
endif()

set(VMILL_LOAD vmill-load-${REMILL_LLVM_VERSION})
add_executable(${VMILL_LOAD}
    Load.cpp
)

target_link_libraries(${VMILL_LOAD} PRIVATE vmill ${PROJECT_LIBRARIES})
target_include_directories(${VMILL_LOAD} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES} third_party/ELFIO)
target_compile_definitions(${VMILL_LOAD} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${VMILL_LOAD} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

install(
    TARGETS ${VMILL_LOAD}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

if(NOT APPLE)
    set(VMILL_SNAPSHOT vmill-snapshot-${REMILL_LLVM_VERSION})
    
    add_executable(${VMILL_SNAPSHOT}
        Snapshot.cpp
        vmill/Arch/X86/Snapshot.cpp
        vmill/Arch/AArch64/Snapshot.cpp
    )
    
    target_link_libraries(${VMILL_SNAPSHOT} PRIVATE vmill ${PROJECT_LIBRARIES})
    target_include_directories(${VMILL_SNAPSHOT} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
    target_compile_definitions(${VMILL_SNAPSHOT} PUBLIC ${PROJECT_DEFINITIONS})
    set_target_properties(${VMILL_SNAPSHOT} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})
    
    install(
        TARGETS ${VMILL_SNAPSHOT}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
    )
 endif()
