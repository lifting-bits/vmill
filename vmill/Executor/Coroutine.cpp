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

#include "vmill/Executor/Coroutine.h"

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

Coroutine::Coroutine(void)
    : stack_end(&(stack[1])),
      fpu_rounding_mode(0),
      _padding0(0) {}

void Coroutine::Pause(Task *task) {
  task->status = kTaskStatusResumable;
  fpu_rounding_mode = std::fegetround();
  __vmill_yield_async(stack_end);
}

void Coroutine::Resume(Task *task) {
  task->status = kTaskStatusRunnable;
  std::fesetround(fpu_rounding_mode);
  __vmill_yield_async(stack_end);
}

}  // namespace vmill
