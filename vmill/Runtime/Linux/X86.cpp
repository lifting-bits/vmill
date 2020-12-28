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
uint64_t DR0;
uint64_t DR1;
uint64_t DR2;
uint64_t DR3;
uint64_t DR4;
uint64_t DR5;
uint64_t DR6;
uint64_t DR7;

// Control regs.
CR0Reg CR0;
CR1Reg CR1;
CR2Reg CR2;
CR3Reg CR3;
CR4Reg CR4;
CR8Reg CR8;

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

// 64-bit `syscall` system call ABI.
class Amd64SyscallSystemCall : public X86BaseSystemCall {
 public:
  virtual ~Amd64SyscallSystemCall(void) = default;

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

  // See https://code.woboq.org/linux/linux/arch/x86/entry/entry_64.S.html#106
  addr_t GetArg(Memory *&memory, State *state, int i) const final {
    switch (i) {
      case 0:
        return state->gpr.rdi.aword;
      case 1:
        return state->gpr.rsi.aword;
      case 2:
        return state->gpr.rdx.aword;
      case 3:
        return state->gpr.r10.aword;
      case 4:
        return state->gpr.r8.aword;
      case 5:
        return state->gpr.r9.aword;
      default:
        return 0;
    }
  }
};

#pragma clang diagnostic pop

#include "vmill/Runtime/Linux/SystemCall.cpp"

extern "C" {

Memory *__remill_async_hyper_call(
    State &state, addr_t ret_addr, Memory *memory) {

  switch (state.hyper_call) {
#if 32 == ADDRESS_SIZE_BITS
    case AsyncHyperCall::kX86SysEnter: {
      X86SysEnter32SystemCall syscall;
      auto user_stack = state.gpr.rsp.aword;
      memory = X86SystemCall(memory, &state, syscall);
      if (syscall.Completed()) {
        ret_addr = syscall.GetReturnAddress(memory, &state, ret_addr);
        state.gpr.rip.aword = ret_addr;
        state.gpr.rsp.aword = user_stack;
        __vmill_set_location(ret_addr, vmill::kTaskStoppedAfterHyperCall);
      }
      break;
    }

    case AsyncHyperCall::kX86IntN:
      if (0x80 == state.hyper_call_vector) {
        X86Int0x80SystemCall syscall;
        memory = X86SystemCall(memory, &state, syscall);
        if (syscall.Completed()) {
          ret_addr = syscall.GetReturnAddress(memory, &state, ret_addr);
          state.gpr.rip.aword = ret_addr;
          __vmill_set_location(ret_addr, vmill::kTaskStoppedAfterHyperCall);
        }
      }
      break;
#endif

#if 64 == ADDRESS_SIZE_BITS
    case AsyncHyperCall::kX86SysCall: {
      Amd64SyscallSystemCall syscall;
      memory = AMD64SystemCall(memory, &state, syscall);
      if (syscall.Completed()) {
        ret_addr = syscall.GetReturnAddress(memory, &state, ret_addr);
        state.gpr.rip.aword = ret_addr;
        state.gpr.rcx.aword = ret_addr;
        __vmill_set_location(ret_addr, vmill::kTaskStoppedAfterHyperCall);
      }
      break;
    }
#endif
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
      if (kLinuxMinIndexForTLSInGDT <= state.seg.gs.index &&
          kLinuxMaxIndexForTLSInGDT >= state.seg.gs.index) {
        auto index = state.seg.gs.index;
        state.addr.gs_base.dword = \
            task->tls_slots[index - kLinuxMinIndexForTLSInGDT].base_addr;
        STRACE_SUCCESS(
            sync_hyper_call, "kX86SetSegmentGS index=%u rpi=%u ti=%u gsbase=%x",
            index, state.seg.gs.rpi, state.seg.gs.ti,
            state.addr.gs_base.dword);
      } else {
        STRACE_ERROR(sync_hyper_call, "kX86SetSegmentGS index=%u rpi=%u ti=%u",
                     state.seg.gs.index, state.seg.gs.rpi, state.seg.gs.ti);
      }
      break;

    case SyncHyperCall::kX86SetSegmentFS:
      if (kLinuxMinIndexForTLSInGDT <= state.seg.fs.index &&
          kLinuxMaxIndexForTLSInGDT >= state.seg.fs.index) {
        auto index = state.seg.fs.index;
        state.addr.fs_base.dword = \
            task->tls_slots[index - kLinuxMinIndexForTLSInGDT].base_addr;
        STRACE_SUCCESS(
            sync_hyper_call, "kX86SetSegmentFS index=%u rpi=%u ti=%u fsbase=%x",
            index, state.seg.fs.rpi, state.seg.fs.ti,
            state.addr.fs_base.dword);
      } else {
        STRACE_ERROR(sync_hyper_call, "kX86SetSegmentFS index=%u rpi=%u ti=%u",
                     state.seg.fs.index, state.seg.fs.rpi, state.seg.fs.ti);
      }
      break;

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
    case SyncHyperCall::kX86CPUID: {
      auto eax = state.gpr.rax.dword;
      auto ecx = state.gpr.rcx.dword;
      asm volatile(
          "cpuid"
          : "=a"(state.gpr.rax.dword),
            "=b"(state.gpr.rbx.dword),
            "=c"(state.gpr.rcx.dword),
            "=d"(state.gpr.rdx.dword)
          : "a"(eax),
            "c"(ecx)
      );
      STRACE_SUCCESS(
          sync_hyper_call, "kX86CPUID eax=%x ecx=%x -> eax=%x ebx=%x ecx=%x edx=%x",
          eax, ecx,
          state.gpr.rax.dword, state.gpr.rbx.dword,
          state.gpr.rcx.dword, state.gpr.rdx.dword);
      break;
    }

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

#endif  // defined(__x86_64__) || defined(__i386__) || defined(_M_X86)

    default:
      STRACE_ERROR(sync_hyper_call, "%u", call);
      __builtin_trap();
      break;
  }

  return mem;
}

}  // extern C
