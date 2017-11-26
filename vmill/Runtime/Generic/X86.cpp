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

struct RegTraceEntry {
  uint64_t rip;
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t rbp;
  uint64_t rsp;
};

enum : size_t {
  kNumEntries = 4096,
};

size_t __vmill_x86_reg_trace_entry = 0;
RegTraceEntry __vmill_x86_reg_trace_table[kNumEntries];

Memory *__vmill_breakpoint(State *state, vmill::PC pc, Memory *memory) {
  auto index = __vmill_x86_reg_trace_entry++ % kNumEntries;
  auto &entry = __vmill_x86_reg_trace_table[index];
  entry.rip = state->gpr.rip.aword;
  entry.rax = state->gpr.rax.aword;
  entry.rbx = state->gpr.rbx.aword;
  entry.rcx = state->gpr.rcx.aword;
  entry.rdx = state->gpr.rdx.aword;
  entry.rsi = state->gpr.rsi.aword;
  entry.rdi = state->gpr.rdi.aword;
  entry.rbp = state->gpr.rbp.aword;
  entry.rsp = state->gpr.rsp.aword;
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

