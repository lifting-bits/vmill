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

#include <cfenv>
#include <cstdint>

#ifndef VMILL_EXECUTOR_COROUTINE_H_
#define VMILL_EXECUTOR_COROUTINE_H_

#include "vmill/Runtime/Task.h"

struct ArchState;
struct Memory;

namespace vmill {

struct Task;
enum class PC : uint64_t;

// A compiled lifted trace.
using LiftedFunction = Memory *(ArchState *, PC, Memory *);


extern "C" {

// Implemented in assembly.
extern void __vmill_execute_async(Task *, LiftedFunction *);

extern void __vmill_yield_async(void *);

}  // extern "C"

// Coroutine that implements
class Coroutine {
 public:
  Coroutine(void)
      : stack_end(&(stack[1])),
        fpu_rounding_mode(0) {}

  [[gnu::noinline]]
  void Yield(void) {
    fpu_rounding_mode = std::fegetround();
    __vmill_yield_async(stack_end);
  }

  [[gnu::noinline]]
  void Resume(void) {
    std::fesetround(fpu_rounding_mode);
    __vmill_yield_async(stack_end);
  }

 private:
  Coroutine(const Coroutine &) = delete;
  Coroutine(const Coroutine &&) = delete;
  void operator=(const Coroutine &) = delete;
  void operator=(const Coroutine &&) = delete;

  struct alignas(16) Stack {
    uint64_t stack[(4096 * 8) / sizeof(uint64_t)];
  };

  // Convenient pointer into `stack`.
  Stack * const stack_end;

  // Rounding mode at the time of a yield/resume.
  int fpu_rounding_mode;

  // The stack on which the coroutine executes.
  Stack stack[1];
};

}  // namespace vmill

#endif  // VMILL_EXECUTOR_COROUTINE_H_
