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

# remill
if("${PLATFORM_NAME}" STREQUAL "windows")
  set(REMILL_FINDPACKAGE_HINTS HINTS "${CMAKE_INSTALL_PREFIX}/remill/lib")
endif()

find_package(remill REQUIRED ${REMILL_FINDPACKAGE_HINTS})

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/settings.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/BCCompiler.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccache.cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

configureCcache()
FindAndSelectClangCompiler()

enable_language(ASM)

set(VMILL_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
set(VMILL_TOOLS_DIR "${PROJECT_SOURCE_DIR}/tools")

# warnings and compiler settings
if(NOT DEFINED WIN32)
  set(PROJECT_CXXFLAGS
    ${GLOBAL_CXXFLAGS} -Werror -Wconversion -pedantic 
    -Wno-unreachable-code-return 
  )
endif()

find_package(ZLIB REQUIRED)

set(ENABLE_ROARING_TESTS OFF CACHE BOOL "CRoaring tests")
set(ROARING_BUILD_STATIC ON CACHE BOOL "CRoaring static build")
add_subdirectory(third_party/CRoaring)

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

    # tools/TaintTracker/TaintTracker.cpp
    # tools/TaintTracker/DataFlowTracker.cpp
        
    third_party/liballoc/liballoc.c
    third_party/ThreadPool/ThreadPool.cpp
    third_party/xxHash/xxhash.c
)

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)


# add everything as public.
target_link_libraries(${PROJECT_NAME} PUBLIC
  remill ${ROARING_LIB_NAME} ${ZLIB_LIBRARIES})
  
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC third_party/CRoaring/include ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS})
#set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

set(VMILL_INCLUDEDIRECTORIES ${PROJECT_INCLUDEDIRECTORIES})

add_subdirectory(vmill/Runtime)

set(VMILL_EXECUTE vmill-execute-${REMILL_LLVM_VERSION})

add_executable(${VMILL_EXECUTE}
    Execute.cpp
)

target_link_libraries(${VMILL_EXECUTE} PRIVATE vmill ${PROJECT_LIBRARIES})
target_include_directories(${VMILL_EXECUTE} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${VMILL_EXECUTE} PUBLIC ${PROJECT_DEFINITIONS})
#set_target_properties(${VMILL_EXECUTE} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

install(
    TARGETS ${VMILL_EXECUTE}
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
    #set_target_properties(${VMILL_SNAPSHOT} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})
    
    install(
        TARGETS ${VMILL_SNAPSHOT}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
    )
 endif()
