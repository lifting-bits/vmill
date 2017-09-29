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

project(grr)
cmake_minimum_required (VERSION 3.2)

set(GRR_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
list(APPEND PROJECT_INCLUDEDIRECTORIES "${PROJECT_SOURCE_DIR}")
#list(APPEND PROJECT_INCLUDEDIRECTORIES "${VMILL_SOURCE_DIR}")
#list(APPEND PROJECT_INCLUDEDIRECTORIES "${VMILL_TOOLS_DIR}")

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
protobuf_generate_cpp(PROJECT_PROTOBUFSOURCEFILES PROJECT_PROTOBUFHEADERFILES "${CMAKE_CURRENT_SOURCE_DIR}/Snapshot.proto")
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_CURRENT_BINARY_DIR})

# disable -Werror on these file since they have been generated
set_source_files_properties(${PROJECT_PROTOBUFSOURCEFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion")
set_source_files_properties(${PROJECT_PROTOBUFHEADERFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion")

#list(APPEND PROJECT_DEFINITIONS "VMILL_INSTALL_RUNTIME_DIR=\"${CMAKE_INSTALL_PREFIX}/share/vmill/${REMILL_LLVM_VERSION}/runtime/\"")
#list(APPEND PROJECT_DEFINITIONS "VMILL_BUILD_RUNTIME_DIR=\"${CMAKE_CURRENT_BINARY_DIR}/vmill/Runtime/\"")

set(GRRSHOT grr-snapshot-${REMILL_LLVM_VERSION})
set(GRRPLAY grr-exec-${REMILL_LLVM_VERSION})

add_executable(${GRRSHOT}
    ${PROJECT_PROTOBUFSOURCEFILES}
    X86/Snapshot.cpp
    Snapshot.cpp
)

#add_compile_options(
#    -DINSTALL_RUNTIME_DIR="${CMAKE_INSTALL_PREFIX}/share/vmill/runtime/"
#    -DBUILD_RUNTIME_DIR="${CMAKE_CURRENT_BINARY_DIR}/tools/vmill/Runtime/"
#)

# Note: grr-snapshot does not need vmill, just remill.
target_link_libraries(${GRRSHOT} PRIVATE remill ${PROJECT_LIBRARIES})
target_include_directories(${GRRSHOT} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${GRRSHOT} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${GRRSHOT} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

add_executable(${GRRPLAY}
    ${PROJECT_PROTOBUFSOURCEFILES}
    Execute.cpp
)

target_link_libraries(${GRRPLAY} PRIVATE vmill ${PROJECT_LIBRARIES})
target_include_directories(${GRRPLAY} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${GRRPLAY} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${GRRPLAY} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

#add_custom_target(runtime)
#add_dependencies(runtime semantics)
#add_subdirectory(Runtime)
#add_dependencies(${GRRSHOT} runtime)
#add_dependencies(${GRRPLAY} runtime)

install(
    TARGETS ${GRRSHOT} ${GRRPLAY}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
