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

#include <iomanip>
#include <ostream>

#include "remill/Arch/AArch64/Runtime/State.h"

#include "vmill/Runtime/Task.h"

namespace vmill {
namespace {

static void LogGPR(std::ostream &os, const Reg &reg, const char *name) {
  os << "  " << name << " " << std::hex << std::setw(16)
     << std::setfill('0') << reg.qword << " at "
     << &reg << std::endl;
}

}  // namespace

void LogAArch64RegisterState(std::ostream &os, const ArchState *state_) {
  auto &state = *reinterpret_cast<const State *>(state_);

  os << "Register state:" << std::endl;
  LogGPR(os, state.gpr.pc, "PC");
  LogGPR(os, state.gpr.sp, "SP");
  LogGPR(os, state.gpr.x0, "X0");
  LogGPR(os, state.gpr.x1, "X1");
  LogGPR(os, state.gpr.x2, "X2");
  LogGPR(os, state.gpr.x3, "X3");
  LogGPR(os, state.gpr.x4, "X4");
  LogGPR(os, state.gpr.x5, "X5");
  LogGPR(os, state.gpr.x6, "X6");
  LogGPR(os, state.gpr.x7, "X7");
  LogGPR(os, state.gpr.x8, "X8");
  LogGPR(os, state.gpr.x9, "X9");
  LogGPR(os, state.gpr.x10, "X10");
  LogGPR(os, state.gpr.x11, "X11");
  LogGPR(os, state.gpr.x12, "X12");
  LogGPR(os, state.gpr.x13, "X13");
  LogGPR(os, state.gpr.x14, "X14");
  LogGPR(os, state.gpr.x15, "X15");
  LogGPR(os, state.gpr.x16, "X16");
  LogGPR(os, state.gpr.x17, "X17");
  LogGPR(os, state.gpr.x18, "X18");
  LogGPR(os, state.gpr.x19, "X19");
  LogGPR(os, state.gpr.x20, "X20");
  LogGPR(os, state.gpr.x21, "X21");
  LogGPR(os, state.gpr.x22, "X22");
  LogGPR(os, state.gpr.x23, "X23");
  LogGPR(os, state.gpr.x24, "X24");
  LogGPR(os, state.gpr.x25, "X25");
  LogGPR(os, state.gpr.x26, "X26");
  LogGPR(os, state.gpr.x27, "X27");
  LogGPR(os, state.gpr.x28, "X28");
  LogGPR(os, state.gpr.x29, "X29");
  LogGPR(os, state.gpr.x30, "X30");
}

}  // namespace
