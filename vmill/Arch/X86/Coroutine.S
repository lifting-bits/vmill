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
    .extern SYMBOL(__vmill_execute)

    // Swap off of the Task-specific stack.
    .align 16
    .globl SYMBOL(__vmill_yield_async)
SYMBOL(__vmill_yield_async):
    .cfi_startproc
.Lbegin0:
    // RDI -> Stack *

    // Align to an 8-byte boundary.
    lea rdi, [rdi - 120]

    // Save+restore the callee-saved registers.
    xchg rbx, [rdi + 0]
    xchg rbp, [rdi + 8]
    xchg r12, [rdi + 16]
    xchg r13, [rdi + 24]
    xchg r14, [rdi + 32]
    xchg r15, [rdi + 40]

    // Restore the old stack pointer.
    xchg rsp, [rdi - 8]
    ret

.Lend0:
    .cfi_endproc


    // Swap onto a Task-specific stack.
    .align 16
    .globl SYMBOL(__vmill_execute_async)
SYMBOL(__vmill_execute_async):
    .cfi_startproc
.Lbegin2:
    // RDI -> Task *
    //        0:   State *
    //        8:   PC
    //        16:  Memory *
    //        24:  Coroutine *
    //             0:   Stack *
    // RSI -> LiftedFunction *

    mov rdx, [rdi + 24] // RDX -> Coroutine *

    // Increment the on-stack counter.
    inc dword ptr [rdx + 12]
    push rdx

    mov rdx, [rdx]      // RDX -> Stack *

    // Align to an 8-byte boundary. (1)
    lea rdx, [rdx - 120]

    // Copy the coroutine pointer into the stack for later.
    pop qword ptr [rdx + 48]

    // Save the callee-saved registers for `__vmill_pause_async`, or for this
    // function to restore if it doesn't pause.
    mov [rdx + 0], rbx
    mov [rdx + 8], rbp
    mov [rdx + 16], r12
    mov [rdx + 24], r13
    mov [rdx + 32], r14
    mov [rdx + 40], r15

    xchg rdx, rsp   // Swap stacks.
    push rdx        // Save the old stack pointer (into the old `rdx + 8`)

    call SYMBOL(__vmill_execute)    // Execute lifted code.

    lea rdx, [rsp + 8]              // Compute old RDX (1) above.
    pop rsp                         // Swap stacks.

    // Restore the callee-saved registers. These were saved by us, or by
    // `__vmill_yield_async`.
    mov rbx, [rdx + 0]
    mov rbp, [rdx + 8]
    mov r12, [rdx + 16]
    mov r13, [rdx + 24]
    mov r14, [rdx + 32]
    mov r15, [rdx + 40]

    // Decrement the `on_stack` counter.
    mov rdx, [rdx + 48]
    dec dword ptr [rdx + 12]

    ret
.Lend2:
    .cfi_endproc

#endif  // defined(__x86_64__)
