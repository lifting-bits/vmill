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

#include "remill/Arch/X86/Runtime/State.h"
#include "remill/Arch/Runtime/Intrinsics.h"

#include "vmill/Runtime/Generic/Intrinsics.cpp"
#include "vmill/Runtime/Linux/SystemCallABI.cpp"
#include "vmill/Runtime/Linux/SystemCall.cpp"

extern "C" {

Memory *__remill_async_hyper_call(
    State &state, addr_t ret_addr, Memory *memory) {

  switch (state.hyper_call) {
    case AsyncHyperCall::kX86SysEnter: {
      SysEnter32SystemCall abi;
      memory = SystemCall32(memory, &state, abi);
      if (memory) {
        ret_addr = abi.GetReturnAddress(memory, ret_addr);
        state.gpr.rip.aword = ret_addr;
        __vmill_schedule(state, ret_addr, memory,
                         vmill::kTaskStoppedAfterHyperCall);
      }
      break;
    }

    case AsyncHyperCall::kX86IntN:
      if (0x80 == state.hyper_call_vector) {
        Int0x80SystemCall abi;
        memory = SystemCall32(memory, &state, abi);
        if (memory) {
          ret_addr = abi.GetReturnAddress(memory, ret_addr);
          state.gpr.rip.aword = ret_addr;
          __vmill_schedule(state, ret_addr, memory,
                           vmill::kTaskStoppedAfterHyperCall);
        }
      }
      break;

    default:
      __vmill_schedule(
          state, ret_addr, memory, vmill::kTaskStoppedBeforeUnhandledHyperCall);
      break;
  }

  return nullptr;
}

}  // extern C
