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

// 32-bit `int 0x80` system call ABI.
class X86Int0x80SystemCall : public SystemCallABI {
 public:
  virtual ~X86Int0x80SystemCall(void) = default;

  addr_t GetReturnAddress(Memory *, addr_t ret_addr) const override {
    return ret_addr;
  }

  addr_t GetSystemCallNum(Memory *, State *state) const override {
    return state->gpr.rax.aword;
  }

 protected:
  Memory *DoSetReturn(Memory *memory, State *state,
                    addr_t ret_val) const override {
    state->gpr.rax.aword = ret_val;
    return memory;
  }

  bool CanReadArgs(Memory *, State *, int num_args) const override {
    return num_args <= 6;
  }

  // See https://code.woboq.org/linux/linux/arch/x86/entry/entry_64_compat.S.html#283
  addr_t GetArg(Memory *&memory, State *state, int i) const override {
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
class X86SysEnter32SystemCall : public SystemCallABI {
 public:
  virtual ~X86SysEnter32SystemCall(void) = default;

  // Find the return address of this system call.
  addr_t GetReturnAddress(Memory *memory, addr_t ret_addr) const override {
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

  bool CanReadArgs(Memory *memory, State *state, int num_args) const override {
    if (num_args == 6) {
      addr_t arg6_addr = state->gpr.rbp.aword;
      return CanReadMemory(memory, arg6_addr, sizeof(addr_t));
    } else {
      return num_args < 6;
    }
  }

  addr_t GetSystemCallNum(Memory *, State *state) const override {
    return state->gpr.rax.aword;
  }

 protected:
  Memory *DoSetReturn(Memory *memory, State *state,
                      addr_t ret_val) const override {
    state->gpr.rax.aword = ret_val;
    return memory;
  }

  // See https://code.woboq.org/linux/linux/arch/x86/entry/entry_64_compat.S.html#38
  addr_t GetArg(Memory *&memory, State *state, int i) const override {
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

#include "vmill/Runtime/Linux/SystemCall.cpp"

extern "C" {

Memory *__remill_async_hyper_call(
    State &state, addr_t ret_addr, Memory *memory) {

  switch (state.hyper_call) {
    case AsyncHyperCall::kX86SysEnter: {
      X86SysEnter32SystemCall syscall;
      auto user_stack = state.gpr.rsp.aword;
      memory = X86SystemCall(memory, &state, syscall);
      if (syscall.Completed()) {
        ret_addr = syscall.GetReturnAddress(memory, ret_addr);
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
          ret_addr = syscall.GetReturnAddress(memory, ret_addr);
          state.gpr.rip.aword = ret_addr;
          __vmill_set_location(ret_addr, vmill::kTaskStoppedAfterHyperCall);
        }
      }
      break;

    default:
      __vmill_set_location(
          ret_addr, vmill::kTaskStoppedBeforeUnhandledHyperCall);
      break;
  }

  return nullptr;
}

Memory *__remill_sync_hyper_call(
    State &state, Memory *mem, SyncHyperCall::Name call) {

  auto eax = state.gpr.rax.dword;
  auto ebx = state.gpr.rbx.dword;
  auto ecx = state.gpr.rcx.dword;
  auto edx = state.gpr.rdx.dword;
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
#endif  // defined(__x86_64__) || defined(__i386__) || defined(_M_X86)

    default:
      STRACE_ERROR(sync_hyper_call, "%u", call);
      break;
  }

  return mem;
}

}  // extern C
