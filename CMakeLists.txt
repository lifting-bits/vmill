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
    vmill/Arch/AArch64/Log.cpp
    vmill/BC/Compiler.cpp
    vmill/BC/Lifter.cpp
    vmill/BC/Util.cpp
    vmill/Executor/AsyncIO.cpp
    vmill/Executor/CodeCache.cpp
    vmill/Executor/Coroutine.cpp
    vmill/Executor/Executor.cpp
    vmill/Executor/Memory.cpp
    vmill/Executor/Runtime.cpp
    vmill/Program/AddressSpace.cpp
    vmill/Program/MappedRange.cpp
    vmill/Program/Snapshot.cpp
    vmill/Util/AreaAllocator.cpp
    vmill/Util/Hash.cpp
    vmill/Util/Timer.cpp
    vmill/Util/ZoneAllocator.cpp
    vmill/Workspace/Tool.cpp
    vmill/Workspace/Workspace.cpp
    vmill/Etc/liballoc/liballoc.c
    vmill/Etc/ThreadPool/ThreadPool.cpp
    vmill/Etc/xxHash/xxhash.c
)

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)

# add everything as public.
target_link_libraries(${PROJECT_NAME} PUBLIC remill ${ZLIB_LIBRARIES} LLVMCodeGen LLVMAsmPrinter LLVMRuntimeDyld LLVMExecutionEngine LLVMTarget LLVMX86AsmParser LLVMX86AsmPrinter LLVMX86CodeGen LLVMAArch64AsmParser LLVMAArch64AsmPrinter LLVMAArch64CodeGen)
target_include_directories(${PROJECT_NAME} PUBLIC SYSTEM ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

set(VMILL_INCLUDEDIRECTORIES ${PROJECT_INCLUDEDIRECTORIES})

add_subdirectory(vmill/Runtime)

add_subdirectory(tools/snapshot)
add_subdirectory(tools/execute)
#add_subdirectory(tools/microx)
