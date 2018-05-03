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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

extern "C" {

// Debug registers.
uint64_t gDR0;
uint64_t gDR1;
uint64_t gDR2;
uint64_t gDR3;
uint64_t gDR4;
uint64_t gDR5;
uint64_t gDR6;
uint64_t gDR7;

// Control regs.
CR0Reg gCR0;
CR1Reg gCR1;
CR2Reg gCR2;
CR3Reg gCR3;
CR4Reg gCR4;

}  // extern C

class X86BaseSystemCall : public SystemCallABI {
 public:
  virtual ~X86BaseSystemCall(void) {}

  addr_t GetPC(const State *state) const final {
    return state->gpr.rip.aword;
  }

  void SetPC(State *state, addr_t new_pc) const final {
    state->gpr.rip.aword = new_pc;
  }

  void SetSP(State *state, addr_t new_sp) const final {
    state->gpr.rsp.aword = new_sp;
  }

  addr_t GetSystemCallNum(Memory *, State *state) const final {
    return state->gpr.rax.aword;
  }
};

// 32-bit `int 0x80` system call ABI.
class X86Int0x80SystemCall : public X86BaseSystemCall {
 public:
  virtual ~X86Int0x80SystemCall(void) = default;

  addr_t GetReturnAddress(Memory *, State *, addr_t ret_addr) const final {
    return ret_addr;
  }

 protected:
  Memory *DoSetReturn(Memory *memory, State *state,
                      addr_t ret_val) const final {
    state->gpr.rax.aword = ret_val;
    return memory;
  }

  bool CanReadArgs(Memory *, State *, int num_args) const final {
    return num_args <= 6;
  }

  // See https://code.woboq.org/linux/linux/arch/x86/entry/entry_64_compat.S.html#283
  addr_t GetArg(Memory *&memory, State *state, int i) const final {
    switch (i) {
      case 0:
        return state->gpr.rbx.aword;
      case 1:
        return state->gpr.rcx.aword;
      case 2:
        return state->gpr.rdx.aword;
      case 3:
        return state->gpr.rsi.aword;
      case 4:
        return state->gpr.rdi.aword;
      case 5:
        return state->gpr.rbp.aword;
      default:
        return 0;
    }
  }
};

// 32-bit `sysenter` ABI.
class X86SysEnter32SystemCall : public X86BaseSystemCall {
 public:
  virtual ~X86SysEnter32SystemCall(void) = default;

  // Find the return address of this system call.
  addr_t GetReturnAddress(Memory *memory, State *,
                          addr_t ret_addr) const final {
    addr_t addr = ret_addr;
    for (addr_t i = 0; i < 15; ++i) {
      uint8_t b0 = 0;

      if (TryReadMemory(memory, addr + i, &b0)) {
        if (0x90 == b0) {  // NOP.
          continue;
        } else if (0xcd == b0) {  // First byte of `int N` instruction.
          return addr + i + 2;
        } else {
          return addr + i;
        }
      }
    }
    return addr;
  }

  bool CanReadArgs(Memory *memory, State *state, int num_args) const final {
    if (num_args == 6) {
      addr_t arg6_addr = state->gpr.rbp.aword;
      return CanReadMemory(memory, arg6_addr, sizeof(addr_t));
    } else {
      return num_args < 6;
    }
  }

 protected:
  Memory *DoSetReturn(Memory *memory, State *state,
                      addr_t ret_val) const final {
    state->gpr.rax.aword = ret_val;
    return memory;
  }

  // See https://code.woboq.org/linux/linux/arch/x86/entry/entry_64_compat.S.html#38
  addr_t GetArg(Memory *&memory, State *state, int i) const final {
    switch (i) {
      case 0:
        return state->gpr.rbx.aword;
      case 1:
        return state->gpr.rcx.aword;
      case 2:
        return state->gpr.rdx.aword;
      case 3:
        return state->gpr.rsi.aword;
      case 4:
        return state->gpr.rdi.aword;
      case 5:
        return ReadMemory<addr_t>(memory, state->gpr.rbp.aword);
      default:
        return 0;
    }
  }
};

#pragma clang diagnostic pop

extern "C" {

Memory *__remill_async_hyper_call(
    State &state, addr_t ret_addr, Memory *memory) {

  switch (state.hyper_call) {
    case AsyncHyperCall::kX86SysEnter: {
      STRACE_ERROR(async_hyper_call, "kX86SysEnter");
      break;
    }

    case AsyncHyperCall::kX86IntN: {
      STRACE_ERROR(async_hyper_call, "kX86IntN vector=0x%x",
                   state.hyper_call_vector);
      break;
    }

    case AsyncHyperCall::kX86SysCall: {
      STRACE_ERROR(async_hyper_call, "kX86SysCall");
      break;
    }

    case AsyncHyperCall::kX86IRet: {
      STRACE_SUCCESS(async_hyper_call, "kX86IRet");
      __vmill_set_location(
          ret_addr, vmill::kTaskStoppedAtReturnTarget);
      return memory;
    }

    default:
      __vmill_set_location(
          ret_addr, vmill::kTaskStoppedBeforeUnhandledHyperCall);
      break;
  }

  return nullptr;
}

Memory *__remill_sync_hyper_call(
    State &state, Memory *mem, SyncHyperCall::Name call) {

  auto task = __vmill_current();

  switch (call) {
    case SyncHyperCall::kAssertPrivileged:
      STRACE_SUCCESS(sync_hyper_call, "kAssertPrivileged pc=%" PRIxADDR,
                     state.gpr.rip.aword);
      break;
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

    case SyncHyperCall::kX86CPUID: {
      auto eax = state.gpr.rax.dword;
      auto ecx = state.gpr.rcx.dword;
      state.gpr.rax.aword = 0;
      state.gpr.rbx.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;
      STRACE_SUCCESS(
          sync_hyper_call, "kX86CPUID eax=%x ecx=%x -> eax=0 ebx=0 ecx=0 edx=0",
          eax, ecx);
      break;
    }

    case SyncHyperCall::kX86ReadTSC:
      state.gpr.rax.aword = 0;
      state.gpr.rdx.aword = 0;
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
      asm volatile(
          "rdtsc"
          : "=a"(state.gpr.rax.dword),
            "=d"(state.gpr.rdx.dword)
      );
#endif  // defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
      STRACE_SUCCESS(sync_hyper_call, "kX86ReadTSC eax=%x edx=%x",
                     state.gpr.rax.dword, state.gpr.rdx.dword);
      break;

    case SyncHyperCall::kX86ReadTSCP:
      state.gpr.rax.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
      asm volatile(
          "rdtscp"
          : "=a"(state.gpr.rax.dword),
            "=c"(state.gpr.rcx.dword),
            "=d"(state.gpr.rdx.dword)
      );
#endif  // defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
      STRACE_SUCCESS(sync_hyper_call, "kX86ReadTSCP eax=%x ecx=%x edx=%x",
                     state.gpr.rax.dword, state.gpr.rcx.dword,
                     state.gpr.rdx.dword);
      break;

    case SyncHyperCall::kX86LoadGlobalDescriptorTable:
      STRACE_ERROR(
          sync_hyper_call,
          "kX86LoadGlobalDescriptorTable pc=%" PRIxADDR " table=%" PRIxADDR,
          state.gpr.rip.aword, static_cast<addr_t>(state.addr_to_load));
      break;

    case SyncHyperCall::kX86SetDebugReg:
      STRACE_ERROR(sync_hyper_call, "kX86SetDebugReg pc=%" PRIxADDR,
                   state.gpr.rip.aword);
      break;

    case SyncHyperCall::kAMD64SetDebugReg:
      STRACE_ERROR(sync_hyper_call, "kAMD64SetDebugReg pc=%" PRIxADDR,
                   state.gpr.rip.aword);
      break;

    case SyncHyperCall::kX86SetControlReg:
      STRACE_ERROR(sync_hyper_call, "kX86SetControlReg pc=%" PRIxADDR,
                   state.gpr.rip.aword);
      break;
    case SyncHyperCall::kAMD64SetControlReg:
      STRACE_ERROR(sync_hyper_call, "kAMD64SetControlReg pc=%" PRIxADDR,
                   state.gpr.rip.aword);
      break;

    case SyncHyperCall::kX86EmulateInstruction:
    case SyncHyperCall::kAMD64EmulateInstruction: {
      STRACE_ERROR(sync_hyper_call, "Unsupported instruction at %" PRIxADDR,
                   state.gpr.rip.aword);
      __vmill_set_location(state.gpr.rip.aword,
                           vmill::kTaskStoppedAtUnsupportedInstruction);
      __vmill_yield(task);
      abort();
      break;
    }

    default:
      STRACE_ERROR(sync_hyper_call, "%u", call);
      abort();
      break;
  }

  return mem;
}

}  // extern C
