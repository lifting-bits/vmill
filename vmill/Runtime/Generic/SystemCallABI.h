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

#ifndef VMILL_RUNTIME_SYSTEMCALLABI_H_
#define VMILL_RUNTIME_SYSTEMCALLABI_H_

#include "remill/Arch/Runtime/Types.h"

struct Memory;
struct State;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

// Generic wrapper around accessing arguments passed into a system call, and
// setting the return value from the system call.
class SystemCallABI {
 public:
  SystemCallABI(void)
      : completed(false) {}

  virtual ~SystemCallABI(void) {}

  virtual addr_t GetPC(const State *state) const = 0;
  virtual void SetPC(State *state, addr_t new_pc) const = 0;
  virtual void SetSP(State *state, addr_t new_sp) const = 0;

  bool Completed(void) {
    return completed;
  }

  // Find the return address of this system call.
  virtual addr_t GetReturnAddress(Memory *memory, State *state,
                                  addr_t ret_addr) const = 0;

  template<typename ... Args>
  bool TryGetArgs(Memory *memory, State *state, Args... args) const {
    if (!CanReadArgs(memory, state, sizeof...(Args))) {
      return false;
    }
    GetArgs(memory, state, args...);
    return true;
  }


  template<const uint32_t seq=0, typename Arg, typename ... Args>
  void GetArgs(Memory *memory, State *state, Arg *arg, Args... args) const {
    *arg = GetArg<Arg, seq>(memory, state);
    if constexpr (sizeof...(Args) == 0) {
      return;
    } else {
      return GetArgs<seq + 1>(memory, state, args...);
    }
  }


  template <typename T1>
  bool GetArgs(Memory *memory, State *state, T1 *arg1) const {
    if (!CanReadArgs(memory, state, 1)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    return true;
  }

  template <typename T>
  Memory *SetReturn(Memory *memory, State *state, T val) const {
    completed = true;
    return DoSetReturn(
        memory, state, static_cast<addr_t>(static_cast<long>(val)));
  }

  virtual addr_t GetSystemCallNum(Memory *memory, State *state) const = 0;

 protected:
  template <typename T, int i>
  T GetArg(Memory *memory, State *state) const {
    return static_cast<T>(GetArg(memory, state, i));
  }

  virtual Memory *DoSetReturn(Memory *, State *, addr_t) const = 0;

  virtual bool CanReadArgs(Memory *memory, State *state,
                           int num_args) const = 0;

  virtual addr_t GetArg(Memory *&memory, State *state, int i) const = 0;

  mutable bool completed;
};

#pragma clang diagnostic pop

#endif  // VMILL_RUNTIME_SYSTEMCALLABI_H_
