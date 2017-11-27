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

#define ADDRESS_SIZE_BITS 64
#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 1

#include <iomanip>
#include <ostream>

#include "remill/Arch/X86/Runtime/State.h"

namespace vmill {
namespace {

static void LogGPR32(std::ostream &os, const Reg &reg, const char *name) {
  os << "  " << name << " " << std::hex << std::setw(8)
     << std::setfill('0') << reg.dword << " at "
     << &reg << std::endl;
}

static void LogGPR64(std::ostream &os, const Reg &reg, const char *name) {
  os << "  " << name << " " << std::hex << std::setw(16)
     << std::setfill('0') << reg.qword << " at "
     << &reg << std::endl;
}

}  // namespace

void LogX86RegisterState(std::ostream &os, const ArchState *state_) {
  auto &state = *reinterpret_cast<const State *>(state_);
  os << "Register state:" << std::endl;
  LogGPR32(os, state.gpr.rip, "EIP");
  LogGPR32(os, state.gpr.rsp, "ESP");
  LogGPR32(os, state.gpr.rbp, "EBP");
  LogGPR32(os, state.gpr.rax, "EAX");
  LogGPR32(os, state.gpr.rbx, "EBX");
  LogGPR32(os, state.gpr.rcx, "ECX");
  LogGPR32(os, state.gpr.rdx, "EDX");
  LogGPR32(os, state.gpr.rsi, "ESI");
  LogGPR32(os, state.gpr.rdi, "EDI");
}

void LogAMD64RegisterState(std::ostream &os, const ArchState *state_) {
  auto &state = *reinterpret_cast<const State *>(state_);
  os << "Register state:" << std::endl;
  LogGPR64(os, state.gpr.rip, "RIP");
  LogGPR64(os, state.gpr.rsp, "RSP");
  LogGPR64(os, state.gpr.rbp, "RBP");
  LogGPR64(os, state.gpr.rax, "RAX");
  LogGPR64(os, state.gpr.rbx, "RBX");
  LogGPR64(os, state.gpr.rcx, "RCX");
  LogGPR64(os, state.gpr.rdx, "RDX");
  LogGPR64(os, state.gpr.rsi, "RSI");
  LogGPR64(os, state.gpr.rdi, "RDI");
  LogGPR64(os, state.gpr.r8, "R8");
  LogGPR64(os, state.gpr.r9, "R9");
  LogGPR64(os, state.gpr.r10, "R10");
  LogGPR64(os, state.gpr.r11, "R11");
  LogGPR64(os, state.gpr.r12, "R12");
  LogGPR64(os, state.gpr.r13, "R13");
  LogGPR64(os, state.gpr.r14, "R14");
  LogGPR64(os, state.gpr.r15, "R15");
}

}  // namespace vmill
