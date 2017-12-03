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

// 64-bit `svc` system call ABI.
class AArch64SupervisorCall : public SystemCallABI {
 public:
  virtual ~AArch64SupervisorCall(void) = default;

  addr_t GetPC(const State *state) const override {
    return state->gpr.pc.aword;
  }

  void SetPC(State *state, addr_t new_pc) const override {
    state->gpr.pc.aword = new_pc;
  }

  void SetSP(State *state, addr_t new_sp) const override {
    state->gpr.sp.aword = new_sp;
  }

  addr_t GetReturnAddress(Memory *, addr_t ret_addr) const override {
    return ret_addr;
  }

  addr_t GetSystemCallNum(Memory *, State *state) const override {
    return state->gpr.x8.qword;
  }

 protected:
  Memory *DoSetReturn(Memory *memory, State *state,
                    addr_t ret_val) const override {
    state->gpr.x0.qword = ret_val;
    return memory;
  }

  bool CanReadArgs(Memory *, State *, int num_args) const override {
    return num_args <= 6;
  }

  addr_t GetArg(Memory *&memory, State *state, int i) const override {
    switch (i) {
      case 0:
        return state->gpr.x0.qword;
      case 1:
        return state->gpr.x1.qword;
      case 2:
        return state->gpr.x2.qword;
      case 3:
        return state->gpr.x3.qword;
      case 4:
        return state->gpr.x4.qword;
      case 5:
        return state->gpr.x5.qword;
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
    case AsyncHyperCall::kAArch64SupervisorCall: {
      AArch64SupervisorCall syscall;
      memory = AArch64SystemCall(memory, &state, syscall);
      if (syscall.Completed()) {
        ret_addr = syscall.GetReturnAddress(memory, ret_addr);
        state.gpr.pc.aword = ret_addr;
        __vmill_set_location(ret_addr, vmill::kTaskStoppedAfterHyperCall);
      }
      break;
    }

    default:
      __vmill_set_location(
          ret_addr, vmill::kTaskStoppedBeforeUnhandledHyperCall);
      break;
  }

  return memory;
}

Memory *__remill_sync_hyper_call(
    State &state, Memory *memory, SyncHyperCall::Name call) {

  switch (call) {
    default:
      STRACE_ERROR(sync_hyper_call, "%u", call);
      break;
  }

  return memory;
}

}  // extern C
