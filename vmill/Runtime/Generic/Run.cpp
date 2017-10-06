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

#include <cstdio>

#include "vmill/Runtime/TaskStatus.h"

extern "C" State *__vmill_allocate_state(void) {
  return new State;
}

extern "C" void __vmill_free_state(State *state) {
  delete state;
}

Memory *__remill_sync_hyper_call(
    State &state, Memory *mem, SyncHyperCall::Name call) {
#ifdef VMILL_RUNTIME_X86
  auto eax = state.gpr.rax.dword;
  auto ebx = state.gpr.rbx.dword;
  auto ecx = state.gpr.rcx.dword;
  auto edx = state.gpr.rdx.dword;
#endif  // VMILL_RUNTIME_X86

  switch (call) {
#ifdef VMILL_RUNTIME_X86
    case SyncHyperCall::kX86CPUID:
      state.gpr.rax.aword = 0;
      state.gpr.rbx.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;

      asm volatile(
          "cpuid"
          : "=a"(state.gpr.rax.dword),
            "=b"(state.gpr.rbx.dword),
            "=c"(state.gpr.rcx.dword),
            "=d"(state.gpr.rdx.dword)
          : "a"(eax),
            "b"(ebx),
            "c"(ecx),
            "d"(edx)
      );
      break;

    case SyncHyperCall::kX86ReadTSC:
      state.gpr.rax.aword = 0;
      state.gpr.rdx.aword = 0;
# if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
      asm volatile(
          "rdtsc"
          : "=a"(state.gpr.rax.dword),
            "=d"(state.gpr.rdx.dword)
      );
# else
      fprintf(stderr, "rdtscp unimplemented!!\n");
# endif
      break;

    case SyncHyperCall::kX86ReadTSCP:
      state.gpr.rax.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;
# if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
      asm volatile(
          "rdtscp"
          : "=a"(state.gpr.rax.dword),
            "=c"(state.gpr.rcx.dword),
            "=d"(state.gpr.rdx.dword)
      );
# else
      fprintf(stderr, "rdtscp unimplemented!!\n");
# endif
      break;
#endif  // VMILL_RUNTIME_X86

    default:
      __builtin_unreachable();
  }

  return mem;
}

// Called by the executor when it wants to run a thread.
extern "C" void __vmill_resume(State &state, addr_t pc, Memory *memory,
                               vmill::TaskStatus status,
                               void (*code)(State &, addr_t, Memory *)) {
  code(state, pc, memory);
}
