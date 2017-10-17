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

#include <gflags/gflags.h>
#include <glog/logging.h>

#ifdef __aarch64__
# include <sys/ptrace.h>
# include <sys/user.h>
#endif

#include <cerrno>

#include "remill/Arch/Arch.h"

#include "vmill/Context/Snapshot.h"

#define ADDRESS_SIZE_BITS 64
#include "remill/Arch/AArch64/Runtime/State.h"

DECLARE_uint64(breakpoint);

namespace vmill {

// Copy the register state from the tracee with PID `pid` and TID `tid` into
// the file with FD `fd`.
void CopyAArch64TraceeState(pid_t pid, pid_t tid, int64_t memory_id,
                            snapshot::Program *program) {
#ifdef __aarch64__
  State state = {};
  struct user_regs_struct regs = {};
  ptrace(PTRACE_GETREGS, tid, NULL, &regs);

  // Copy in the general-purpose registers.
  auto &gpr = state.gpr;
  gpr.x0.qword = regs.regs[0];
  gpr.x1.qword = regs.regs[1];
  gpr.x2.qword = regs.regs[2];
  gpr.x3.qword = regs.regs[3];
  gpr.x4.qword = regs.regs[4];
  gpr.x5.qword = regs.regs[5];
  gpr.x6.qword = regs.regs[6];
  gpr.x7.qword = regs.regs[7];
  gpr.x8.qword = regs.regs[8];
  gpr.x9.qword = regs.regs[9];
  gpr.x10.qword = regs.regs[10];
  gpr.x11.qword = regs.regs[11];
  gpr.x12.qword = regs.regs[12];
  gpr.x13.qword = regs.regs[13];
  gpr.x14.qword = regs.regs[14];
  gpr.x15.qword = regs.regs[15];
  gpr.x16.qword = regs.regs[16];
  gpr.x17.qword = regs.regs[17];
  gpr.x18.qword = regs.regs[18];
  gpr.x19.qword = regs.regs[19];
  gpr.x20.qword = regs.regs[20];
  gpr.x21.qword = regs.regs[21];
  gpr.x22.qword = regs.regs[22];
  gpr.x23.qword = regs.regs[23];
  gpr.x24.qword = regs.regs[24];
  gpr.x25.qword = regs.regs[25];
  gpr.x26.qword = regs.regs[26];
  gpr.x27.qword = regs.regs[27];
  gpr.x28.qword = regs.regs[28];
  gpr.x29.qword = regs.regs[29];
  gpr.x30.qword = regs.regs[30];

  gpr.sp.qword = regs.sp;
  gpr.pc.qword = regs.sp;

  PSTATE pstate = {};
  pstate.flat = regs.pstate;

  state.nzcv.n = pstate.N;
  state.nzcv.z = pstate.Z;
  state.nzcv.c = pstate.C;
  state.nzcv.v = pstate.V;

  state.sr.n = state.nzcv.n;
  state.sr.z = state.nzcv.z;
  state.sr.c = state.nzcv.c;
  state.sr.v = state.nzcv.v;

  if (FLAGS_breakpoint) {
    gpr.pc.qword -= 4;  // Subtract off size of an instruction.
  }

  struct user_fpsimd_struct fpregs = {};
  ptrace(PTRACE_GETFPREGS, tid, NULL, &fpregs);
  state.fpsr.flat = fpregs.fpsr;
  state.fpcr.flat = fpregs.fpcr;
  state.sr.idc = state.fpsr.idc;
  state.sr.ofc = state.fpsr.ofc;
  state.sr.ixc = state.fpsr.ixc;
  state.sr.ufc = state.fpsr.ufc;

  for (unsigned i = 0; i < 32; ++i) {
    state.simd.v[i].dqwords.elems[0] = fpregs.vregs[i];
  }

  auto thread_info = program->add_tasks();
  thread_info->set_pc(static_cast<int64_t>(gpr.pc.qword));
  thread_info->set_state(&state, sizeof(State));
  thread_info->set_address_space_id(memory_id);

  LOG(INFO)
      << "Copying register state for PID " << std::dec << pid
      << " and TID " << std::dec << tid << std::endl
      << "  x0 = " << std::hex << gpr.x0.qword << std::endl
      << "  x1 = " << std::hex << gpr.x1.qword << std::endl
      << "  x2 = " << std::hex << gpr.x2.qword << std::endl
      << "  x3 = " << std::hex << gpr.x3.qword << std::endl
      << "  x4 = " << std::hex << gpr.x4.qword << std::endl
      << "  x5 = " << std::hex << gpr.x5.qword << std::endl
      << "  x6 = " << std::hex << gpr.x6.qword << std::endl
      << "  x7 = " << std::hex << gpr.x7.qword << std::endl
      << "  x8 = " << std::hex << gpr.x8.qword << std::endl
      << "  x9 = " << std::hex << gpr.x9.qword << std::endl
      << "  x10 = " << std::hex << gpr.x10.qword << std::endl
      << "  x11 = " << std::hex << gpr.x11.qword << std::endl
      << "  x12 = " << std::hex << gpr.x12.qword << std::endl
      << "  x13 = " << std::hex << gpr.x13.qword << std::endl
      << "  x14 = " << std::hex << gpr.x14.qword << std::endl
      << "  x15 = " << std::hex << gpr.x15.qword << std::endl
      << "  x16 = " << std::hex << gpr.x16.qword << std::endl
      << "  x17 = " << std::hex << gpr.x17.qword << std::endl
      << "  x18 = " << std::hex << gpr.x18.qword << std::endl
      << "  x19 = " << std::hex << gpr.x19.qword << std::endl
      << "  x20 = " << std::hex << gpr.x20.qword << std::endl
      << "  x21 = " << std::hex << gpr.x21.qword << std::endl
      << "  x22 = " << std::hex << gpr.x22.qword << std::endl
      << "  x23 = " << std::hex << gpr.x23.qword << std::endl
      << "  x24 = " << std::hex << gpr.x24.qword << std::endl
      << "  x25 = " << std::hex << gpr.x25.qword << std::endl
      << "  x26 = " << std::hex << gpr.x26.qword << std::endl
      << "  x27 = " << std::hex << gpr.x27.qword << std::endl
      << "  x28 = " << std::hex << gpr.x28.qword << std::endl
      << "  x29 = " << std::hex << gpr.x29.qword << std::endl
      << "  x30 = " << std::hex << gpr.x30.qword << std::endl
      << "  PC = " << std::hex << gpr.pc.qword << std::endl
      << "  SP = " << std::hex << gpr.sp.qword << std::endl
      << "  TPIDR = " << std::dec << state.sr.tpidr_el0.qword << std::endl
      << "  TPIDRRO = " << std::hex << state.sr.tpidrro_el0.qword << std::endl
      << std::dec;
#else
  LOG(FATAL)
      << "Cannot snapshot x86 program using non-x86_64 build.";

  (void) pid;
  (void) tid;
  (void) memory_id;
  (void) program;
#endif  // __aarch64__
}

}  // namespace vmill

