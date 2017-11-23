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

#include "vmill/Runtime/Task.h"

// Initialize a task.
static void __vmill_init_task(
    vmill::Task *task, const void *state, vmill::PC pc,
    vmill::AddressSpace *memory) {

  task->state = new State;
  task->pc = pc;
  task->status = vmill::kTaskStatusRunnable;
  task->location = vmill::kTaskNotYetStarted;
  task->memory = memory;

  memcpy(task->state, state, sizeof(State));

  // Initialize this task's floating point environment based on the
  // arch-specific info in the `State` structure.
  fenv_t old_env = {};
  fegetenv(&old_env);
  feclearexcept(FE_ALL_EXCEPT);
  fesetenv(FE_DFL_ENV);
  __vmill_init_fpu_environ(*reinterpret_cast<State *>(task->state));
  fegetenv(&(task->floating_point_env));
  fesetenv(&old_env);
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
    case SyncHyperCall::kX86SetSegmentES:
      STRACE_ERROR(sync_hyper_call, "kX86SetSegmentES index=%u rpi=%u ti=%u",
                   state.seg.es.index, state.seg.es.rpi, state.seg.es.ti);
      break;
    case SyncHyperCall::kX86SetSegmentSS:
      STRACE_ERROR(sync_hyper_call, "kX86SetSegmentSS index=%u rpi=%u ti=%u",
                   state.seg.ss.index, state.seg.ss.rpi, state.seg.ss.ti);
      break;
    case SyncHyperCall::kX86SetSegmentDS:
      STRACE_ERROR(sync_hyper_call, "kX86SetSegmentDS index=%u rpi=%u ti=%u",
                   state.seg.ds.index, state.seg.ds.rpi, state.seg.ds.ti);
      break;
    case SyncHyperCall::kX86SetSegmentGS:
      STRACE_ERROR(sync_hyper_call, "kX86SetSegmentGS index=%u rpi=%u ti=%u",
                   state.seg.gs.index, state.seg.gs.rpi, state.seg.gs.ti);
      break;
    case SyncHyperCall::kX86SetSegmentFS:
      STRACE_ERROR(sync_hyper_call, "kX86SetSegmentFS index=%u rpi=%u ti=%u",
                   state.seg.fs.index, state.seg.fs.rpi, state.seg.fs.ti);
      break;

# if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
    case SyncHyperCall::kX86CPUID:
      STRACE_SUCCESS(sync_hyper_call, "kX86CPUID eax=%x ebx=%x ecx=%x edx=%x",
                     eax, ebx, ecx, edx);
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
      asm volatile(
          "rdtsc"
          : "=a"(state.gpr.rax.dword),
            "=d"(state.gpr.rdx.dword)
      );
      STRACE_SUCCESS(sync_hyper_call, "kX86ReadTSC eax=%x edx=%x",
                     state.gpr.rax.dword, state.gpr.rdx.dword);
      break;

    case SyncHyperCall::kX86ReadTSCP:
      state.gpr.rax.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;
      asm volatile(
          "rdtscp"
          : "=a"(state.gpr.rax.dword),
            "=c"(state.gpr.rcx.dword),
            "=d"(state.gpr.rdx.dword)
      );
      STRACE_SUCCESS(sync_hyper_call, "kX86ReadTSCP eax=%x ecx=%x edx=%x",
                     state.gpr.rax.dword, state.gpr.rcx.dword,
                     state.gpr.rdx.dword);
      break;
# endif  // defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
#endif  // VMILL_RUNTIME_X86

    default:
      STRACE_ERROR(sync_hyper_call, "%u", call);
      break;
  }

  return mem;
}
