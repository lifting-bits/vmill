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

if (NOT TARGET remill)
    # Remill's  CMake definitions are required to build to bitcode
    message(FATAL_ERROR "The remill target does not exists!")
endif ()

function(add_runtime_helper os arch address_bit_size)
    message(" > Generating runtime target: ${target_name}")
    
    set(target_name ${os}_${arch})
    
    add_runtime(${target_name}
        SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/${target_name}.cpp"
        ADDRESS_SIZE ${address_bit_size}
        INCLUDEDIRECTORIES "${REMILL_INCLUDE_LOCATION}" "${PROJECT_SOURCE_DIR}"
        INSTALLDESTINATION "share/vmill/${REMILL_LLVM_VERSION}/runtime"
        BCFLAGS -Wno-format)
endfunction()

add_runtime_helper(linux x86 32)
add_runtime_helper(linux x86_avx 32)

add_runtime_helper(linux amd64 64)
add_runtime_helper(linux amd64_avx 64)

add_runtime_helper(linux aarch64 64)

