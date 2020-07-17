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

  template <typename T1>
  bool TryGetArgs(Memory *memory, State *state, T1 *arg1) const {
    if (!CanReadArgs(memory, state, 1)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    return true;
  }

  template <typename T1, typename T2>
  bool TryGetArgs(Memory *memory, State *state, T1 *arg1, T2 *arg2) const {
    if (!CanReadArgs(memory, state, 2)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    return true;
  }

  template <typename T1, typename T2, typename T3>
  bool TryGetArgs(Memory *memory, State *state, T1 *arg1, T2 *arg2,
                  T3 *arg3) const {
    if (!CanReadArgs(memory, state, 3)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    *arg3 = GetArg<T3, 2>(memory, state);
    return true;
  }

  template <typename T1, typename T2, typename T3, typename T4>
  bool TryGetArgs(Memory *memory, State *state, T1 *arg1, T2 *arg2,
                  T3 *arg3, T4 *arg4) const {
    if (!CanReadArgs(memory, state, 4)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    *arg3 = GetArg<T3, 2>(memory, state);
    *arg4 = GetArg<T4, 3>(memory, state);
    return true;
  }

  template <typename T1, typename T2, typename T3, typename T4, typename T5>
  bool TryGetArgs(Memory *memory, State *state, T1 *arg1, T2 *arg2,
                  T3 *arg3, T4 *arg4, T5 *arg5) const {
    if (!CanReadArgs(memory, state, 5)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    *arg3 = GetArg<T3, 2>(memory, state);
    *arg4 = GetArg<T4, 3>(memory, state);
    *arg5 = GetArg<T5, 4>(memory, state);
    return true;
  }

  template <typename T1, typename T2, typename T3, typename T4,
            typename T5, typename T6>
  bool TryGetArgs(Memory *memory, State *state, T1 *arg1, T2 *arg2,
                  T3 *arg3, T4 *arg4, T5 *arg5, T6 *arg6) const {
    if (!CanReadArgs(memory, state, 6)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    *arg3 = GetArg<T3, 2>(memory, state);
    *arg4 = GetArg<T4, 3>(memory, state);
    *arg5 = GetArg<T5, 4>(memory, state);
    *arg6 = GetArg<T6, 5>(memory, state);
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
