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

/* Note:    Apple mangles C symbol names to have a leading underscore. */
#ifdef __APPLE__
# define SYMBOL(x) CAT(_, x)
#else
# define SYMBOL(x) x
#endif

    .intel_syntax noprefix ;
    .text

    .extern SYMBOL(__vmill_execute)

    // Swap onto a Task-specific stack.
    .align 16
    .globl SYMBOL(__vmill_execute_on_stack)
SYMBOL(__vmill_execute_on_stack):
    .cfi_startproc
.Lbegin:
    // RDI -> Task *
    //          offset 0:   State *
    //          offset 8:   PC
    //          offset 16:  Memory *
    // RSI -> LiftedFunction *
    // RDX -> Stack *
    xchg rdx, rsp
    push rdx

    push rbp
    mov rbp, rdx  // Setup a link pointer for the stack

    call SYMBOL(__vmill_execute)

    pop rbp
    pop rsp
    ret
.Lend:
    .cfi_endproc
    .size SYMBOL(__vmill_execute_on_stack),.Lend-.Lbegin
