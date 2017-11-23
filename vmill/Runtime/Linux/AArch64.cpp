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

#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "vmill/Runtime/Generic/Intrinsics.cpp"
#include "vmill/Runtime/Generic/SystemCallABI.h"

// 64-bit `svc` system call ABI.
class AArch64SupervisorCall : public SystemCallABI {
 public:
  virtual ~AArch64SupervisorCall(void) = default;

  addr_t GetReturnAddress(Memory *, addr_t ret_addr) const override {
    return ret_addr;
  }

  Memory *SetReturn(Memory *memory, State *state,
                    addr_t ret_val) const override {
    state->gpr.x0.qword = ret_val;
    return memory;
  }

  addr_t GetSystemCallNum(Memory *, State *state) const override {
    return state->gpr.x8.qword;
  }

 protected:

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
      AArch64SupervisorCall abi;
      memory = AArch64SystemCall(memory, &state, abi);
      if (memory) {
        ret_addr = abi.GetReturnAddress(memory, ret_addr);
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

  return nullptr;
}

}  // extern C
