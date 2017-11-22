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

#pragma STDC FENV_ACCESS ON
#include <fenv.h>

extern "C" {

Memory *__vmill_reg_tracer(State &state, addr_t, Memory *memory) {
  fprintf(
      stderr,
      "PC=%" PRIx64 ",SP=%" PRIx64
      ",X0=%" PRIx64 ",X1=%" PRIx64 ",X2=%" PRIx64 ",X3=%" PRIx64
      ",X4=%" PRIx64 ",X5=%" PRIx64 ",X6=%" PRIx64 ",X7=%" PRIx64
      ",X8=%" PRIx64 ",X9=%" PRIx64 ",X10=%" PRIx64 ",X11=%" PRIx64
      ",X12=%" PRIx64 ",X13=%" PRIx64 ",X14=%" PRIx64 ",X15=%" PRIx64
      ",X16=%" PRIx64 ",X17=%" PRIx64 ",X18=%" PRIx64 ",X19=%" PRIx64
      ",X20=%" PRIx64 ",X21=%" PRIx64 ",X22=%" PRIx64 ",X23=%" PRIx64
      ",X24=%" PRIx64 ",X25=%" PRIx64 ",X26=%" PRIx64 ",X27=%" PRIx64
      ",X28=%" PRIx64 ",X29=%" PRIx64 ",X30=%" PRIx64 "\n",
      state.gpr.pc.qword, state.gpr.sp.qword,
      state.gpr.x0.qword, state.gpr.x1.qword, state.gpr.x2.qword,
      state.gpr.x3.qword, state.gpr.x4.qword, state.gpr.x5.qword,
      state.gpr.x6.qword, state.gpr.x7.qword, state.gpr.x8.qword,
      state.gpr.x9.qword, state.gpr.x10.qword, state.gpr.x11.qword,
      state.gpr.x12.qword, state.gpr.x13.qword, state.gpr.x14.qword,
      state.gpr.x15.qword, state.gpr.x16.qword, state.gpr.x17.qword,
      state.gpr.x18.qword, state.gpr.x19.qword, state.gpr.x20.qword,
      state.gpr.x21.qword, state.gpr.x22.qword, state.gpr.x23.qword,
      state.gpr.x24.qword, state.gpr.x25.qword, state.gpr.x26.qword,
      state.gpr.x27.qword, state.gpr.x28.qword, state.gpr.x29.qword,
      state.gpr.x30.qword);
  return memory;
}

}  // extern C

namespace {

static void __vmill_init_fpu_environ(State &state) {
  int new_round = 0;
  switch (state.fpcr.rmode) {
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
