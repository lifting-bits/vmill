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

#include "vmill/Arch/X86/Util.S"

#if defined(__x86_64__)

    .align 16
    .globl SYMBOL(arch_sys_sigreturn);
SYMBOL(arch_sys_sigreturn):
    .cfi_startproc
#if defined(__linux__)
    mov eax, 15  // `__NR_rt_sigreturn`.
    syscall
#elif defined(__APPLE__)
    ud2;  // TODO(pag): Figure out how to make this syscall.
#else
# error "Unsupported platform."
#endif
    .cfi_endproc
    ud2

#endif  // defined(__x86_64__)
