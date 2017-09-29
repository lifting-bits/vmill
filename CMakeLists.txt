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

set(VMILL_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
set(VMILL_TOOLS_DIR "${PROJECT_SOURCE_DIR}/tools")

list(APPEND PROJECT_INCLUDEDIRECTORIES "${VMILL_SOURCE_DIR}")
list(APPEND PROJECT_INCLUDEDIRECTORIES "${VMILL_TOOLS_DIR}")

list(APPEND PROJECT_DEFINITIONS "VMILL_INSTALL_RUNTIME_DIR=\"${CMAKE_INSTALL_PREFIX}/share/vmill/${REMILL_LLVM_VERSION}/runtime/\"")
list(APPEND PROJECT_DEFINITIONS "VMILL_BUILD_RUNTIME_DIR=\"${CMAKE_CURRENT_BINARY_DIR}/vmill/Runtime/\"")

add_library(${PROJECT_NAME} STATIC
    vmill/Arch/Decoder.cpp
    vmill/BC/Executor.cpp
    vmill/BC/NativeExecutor.cpp
    vmill/BC/Lifter.cpp
    vmill/BC/Runtime.cpp
    vmill/Context/AddressSpace.cpp
    vmill/Context/Context.cpp
)

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)

# add everything as public.
target_link_libraries(${PROJECT_NAME} PUBLIC remill LLVMCodeGen LLVMAsmPrinter LLVMRuntimeDyld LLVMExecutionEngine LLVMTarget LLVMX86AsmParser LLVMX86AsmPrinter LLVMX86CodeGen LLVMAArch64AsmParser LLVMAArch64AsmPrinter LLVMAArch64CodeGen)
target_include_directories(${PROJECT_NAME} PUBLIC SYSTEM ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})


add_subdirectory(vmill/Runtime)

add_subdirectory(tools/grr)
add_subdirectory(tools/microx)
