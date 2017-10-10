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

project(vmill-snapshot)
cmake_minimum_required (VERSION 3.2)

list(APPEND PROJECT_INCLUDEDIRECTORIES "${PROJECT_SOURCE_DIR}")
list(APPEND PROJECT_INCLUDEDIRECTORIES "${VMILL_INCLUDEDIRECTORIES}")

set(VMILL_SNAPSHOT vmill-snapshot-${REMILL_LLVM_VERSION})

add_executable(${VMILL_SNAPSHOT}
    Snapshot.cpp
    X86.cpp
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
