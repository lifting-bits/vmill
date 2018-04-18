/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if defined(__x86_64__)

#include "vmill/Arch/X86/Util.S"

    TEXT_SECTION

    .extern SYMBOL(__vmill_record_read_fault_8)
    .extern SYMBOL(__vmill_record_read_fault_16)
    .extern SYMBOL(__vmill_record_read_fault_32)
    .extern SYMBOL(__vmill_record_read_fault_64)
    .extern SYMBOL(__vmill_record_read_fault_f32)
    .extern SYMBOL(__vmill_record_read_fault_f64)

    .extern SYMBOL(__vmill_record_write_fault_8)
    .extern SYMBOL(__vmill_record_write_fault_16)
    .extern SYMBOL(__vmill_record_write_fault_32)
    .extern SYMBOL(__vmill_record_write_fault_64)
    .extern SYMBOL(__vmill_record_write_fault_f32)
    .extern SYMBOL(__vmill_record_write_fault_f64)

    .data
    .align 16
SYMBOL(__vmill_mem_address):
    .quad 0
SYMBOL(__vmill_mem_value):
    .quad 0
SYMBOL(__vmill_mem_ptr):
    .quad 0

    .text

    /* uint8_t __remill_read_memory_8(vmill::AddressSpace *, addr_t) */

#define MAKE_MEM_READ(i, suffix, cxx_suffix) \
        TEXT_SECTION ; \
        .extern SYMBOL(_ZN5vmill12AddressSpace7TryRead ## cxx_suffix) ; \
        .p2align 4, 0x90; \
        .globl SYMBOL(__remill_read_memory_ ## suffix) ; \
    SYMBOL(__remill_read_memory_ ## suffix): \
    .Ltmp0_ ## i: \
        .cfi_startproc ; \
        push rbp ; \
        mov rbp, rsp ; \
        mov qword ptr [rip + SYMBOL(__vmill_mem_address)], rsi ; \
        lea rdx, qword ptr [rip + SYMBOL(__vmill_mem_value)] ; \
        call SYMBOL(_ZN5vmill12AddressSpace7TryRead ## cxx_suffix) ; \
        test al, al ; \
        jz .Ltmp1_ ## i ; \
        mov rax, qword ptr [rip + SYMBOL(__vmill_mem_value)] ; \
        pop rbp ; \
        ret ; \
        .cfi_endproc ; \
    .Ltmp2_ ## i: \
        .section .text.slow, "ax" ; \
    .Ltmp1_ ## i: \
        mov rdi, qword ptr [rip + SYMBOL(__vmill_mem_address)] ; \
        call SYMBOL(__vmill_record_read_fault_ ## suffix) ; \
        mov rax, qword ptr [rip + SYMBOL(__vmill_mem_value)] ; \
        pop rbp ; \
        ret ;

#if defined(__APPLE__)
MAKE_MEM_READ(0, 8, EyPh)  // Uses `unsigned long long`.
MAKE_MEM_READ(1, 16, EyPt)
MAKE_MEM_READ(2, 32, EyPj)
MAKE_MEM_READ(3, 64, EyPy)
#else
MAKE_MEM_READ(0, 8, EmPh)  // Uses `unsigned long`.
MAKE_MEM_READ(1, 16, EmPt)
MAKE_MEM_READ(2, 32, EmPj)
MAKE_MEM_READ(3, 64, EmPm)
#endif

#undef MAKE_MEM_READ

    /* vmill::AddressSpace *__remill_write_memory_8(vmill::AddressSpace *, addr_t, uint8_t ) */

#define MAKE_MEM_WRITE(i, suffix, cxx_suffix) \
        TEXT_SECTION ; \
        .extern SYMBOL(_ZN5vmill12AddressSpace8TryWriteE ## cxx_suffix) ; \
        .p2align 4, 0x90; \
        .globl SYMBOL(__remill_write_memory_ ## suffix) ; \
    SYMBOL(__remill_write_memory_ ## suffix): \
    .Ltmp0_ ## i: \
        .cfi_startproc ; \
        push rbp ; \
        mov rbp, rsp ; \
        mov qword ptr [rip + SYMBOL(__vmill_mem_address)], rsi ; \
        mov qword ptr [rip + SYMBOL(__vmill_mem_ptr)], rdi ; \
        call SYMBOL(_ZN5vmill12AddressSpace8TryWriteE ## cxx_suffix) ; \
        test al, al ; \
        jz .Ltmp1_ ## i ; \
        mov rax, qword ptr [rip + SYMBOL(__vmill_mem_ptr)] ; \
        pop rbp ; \
        ret ; \
        .cfi_endproc ; \
    .Ltmp2_ ## i: \
        .section .text.slow, "ax" ; \
    .Ltmp1_ ## i: \
        mov rdi, qword ptr [rip + SYMBOL(__vmill_mem_address)] ; \
        call SYMBOL(__vmill_record_write_fault_ ## suffix) ; \
        mov rax, qword ptr [rip + SYMBOL(__vmill_mem_ptr)] ; \
        pop rbp ; \
        ret ; \

#if defined(__APPLE__)
MAKE_MEM_WRITE(4, 8, yh)  // Uses `unsigned long long`.
MAKE_MEM_WRITE(5, 16, yt)
MAKE_MEM_WRITE(6, 32, yj)
MAKE_MEM_WRITE(7, 64, yy)
#else
MAKE_MEM_WRITE(4, 8, mh)  // Uses `unsigned long`.
MAKE_MEM_WRITE(5, 16, mt)
MAKE_MEM_WRITE(6, 32, mj)
MAKE_MEM_WRITE(7, 64, mm)
#endif

#undef MAKE_MEM_WRITE

#endif  // defined(__x86_64__)
