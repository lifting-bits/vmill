# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

function(add_runtime_helper os arch address_bit_size)
    message(" > Generating runtime target: ${target_name}")
    
    set(target_name ${os}_${arch})
    
    add_runtime(${target_name}
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${target_name}.cpp
        ADDRESS_SIZE ${address_bit_size})

    target_include_directories(${target_name} PRIVATE ${REMILL_SOURCE_DIR})
    target_include_directories(${target_name} PRIVATE ${PROJECT_SOURCE_DIR})
    install(TARGETS ${target_name} DESTINATION "share/vmill/${REMILL_LLVM_VERSION}/runtime")

endfunction()

add_runtime_helper(linux x86 32)
add_runtime_helper(linux x86_avx 32)

add_runtime_helper(linux amd64 64)
add_runtime_helper(linux amd64_avx 64)
