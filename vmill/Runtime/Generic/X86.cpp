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

extern "C" {

Memory *__vmill_reg_tracer(State &state, addr_t, Memory *memory) {
#if VMILL_RUNTIME_X86 == 64
  fprintf(
      stderr,
      "RIP=%" PRIx64 ",RAX=%" PRIx64 ",RBX=%" PRIx64
      ",RCX=%" PRIx64 ",RDX=%" PRIx64 ",RSI=%" PRIx64
      ",RDI=%" PRIx64 ",RBP=%" PRIx64 ",RSP=%" PRIx64
      ",R8=%" PRIx64 ",R9=%" PRIx64 ",R10=%" PRIx64
      ",R11=%" PRIx64 ",R12=%" PRIx64 ",R13=%" PRIx64
      ",R14=%" PRIx64 ",R15=%" PRIx64 "\n",

      state.gpr.rip.qword, state.gpr.rax.qword, state.gpr.rbx.qword,
      state.gpr.rcx.qword, state.gpr.rdx.qword, state.gpr.rsi.qword,
      state.gpr.rdi.qword, state.gpr.rbp.qword, state.gpr.rsp.qword,
      state.gpr.r8.qword, state.gpr.r9.qword, state.gpr.r10.qword,
      state.gpr.r11.qword, state.gpr.r12.qword, state.gpr.r13.qword,
      state.gpr.r14.qword, state.gpr.r15.qword);
#else
  fprintf(
      stderr,
      "EIP=%" PRIx32 ",EAX=%" PRIx32 ",EBX=%" PRIx32
      ",ECX=%" PRIx32 ",EDX=%" PRIx32 ",ESI=%" PRIx32
      ",EDI=%" PRIx32 ",ESP=%" PRIx32 ",EBP=%" PRIx32 "\n",
      state.gpr.rip.dword, state.gpr.rax.dword, state.gpr.rbx.dword,
      state.gpr.rcx.dword, state.gpr.rdx.dword, state.gpr.rsi.dword,
      state.gpr.rdi.dword, state.gpr.rbp.dword, state.gpr.rsp.dword);
#endif  // VMILL_RUNTIME_X86
  return memory;
}

}  // extern C

namespace {

static void __vmill_init_fpu_environ(State *state) {
  int new_round = 0;
  switch (state->x87.fxsave.cwd.rc) {
    case kFPURoundToNearestEven:  // RN (round nearest).
      new_round = FE_TONEAREST;
      break;
    case kFPURoundUpInf:  // RP (round toward plus infinity).
      new_round = FE_UPWARD;
      break;
    case kFPURoundDownNegInf:  // RM (round toward minus infinity).
      new_round = FE_DOWNWARD;
      break;
    case kFPURoundToZero:  // RZ (round toward zero).
      new_round = FE_TOWARDZERO;
      break;
  }
  fesetround(new_round);
}

}  // namespace

