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

project(microx)
cmake_minimum_required (VERSION 3.2)

set(MICROX_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
list(APPEND PROJECT_INCLUDEDIRECTORIES "${PROJECT_SOURCE_DIR}")

set(MICROX microx-${REMILL_LLVM_VERSION})

add_executable(${MICROX}
    Execute.cpp
)

target_link_libraries(${MICROX} PRIVATE vmill ${PROJECT_LIBRARIES})
target_include_directories(${MICROX} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${MICROX} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${MICROX} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

install(
    TARGETS ${MICROX}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
