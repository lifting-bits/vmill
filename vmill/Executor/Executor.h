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

#ifndef VMILL_EXECUTOR_EXECUTOR_H_
#define VMILL_EXECUTOR_EXECUTOR_H_

#include <list>
#include <memory>
#include <unordered_map>

#include "vmill/BC/Trace.h"
#include "vmill/Runtime/TaskStatus.h"

struct ArchState;
struct Memory;

namespace llvm {
class LLVMContext;
}  // namespace llvm
namespace vmill {

class AddressSpace;
class CodeCache;
class DecodedTraceList;
class Lifter;

// A task is like a thread, but really, it's the runtime that gives a bit more
// meaning to threads. The runtime has `resume`, `pause`, `stop`, and `schedule`
// intrinsics. When
struct Task {
 public:
  ArchState *state;
  PC pc;
  AddressSpace *memory;
  TaskStatus status;
};

// A queue of tasks. In many cases we only have a single task so we like to
// keep it in `next_task`.
class TaskQueue {
 public:
  TaskQueue(void);
  void Enqueue(const Task &task);
  bool TryDequeue(Task *task_out);

 private:
  bool has_next_task;
  Task next_task;
  std::list<Task> queue;
};

// A compiled lifted trace.
using LiftedFunction = Memory *(ArchState *, PC, Memory *);

// Task executor. This manages things like the code cache, and can lift and
// compile code on request.
class Executor {
 public:
  Executor(void);

  void Execute(void);

  void AddInitialTask(const std::string &state, PC pc, AddressSpace *memory);
  void EnqueueTask(const Task &task);

 private:
  void Execute(const Task &task);

  __attribute__((noinline))
  void DecodeTracesFromTask(const Task &task);

  __attribute__((noinline))
  void LiftDecodedTraces(const DecodedTraceList &traces);

  std::shared_ptr<llvm::LLVMContext> context;
  std::unique_ptr<Lifter> lifter;
  std::unique_ptr<CodeCache> code_cache;
  TaskQueue task_queue;

  // Map of "live traces". Instead of mapping PCs to lifted function, we map
  // tuples of (PC, CodeVersion) to lifted functions. These code versions
  // permit multiple address spaces to be simultaneously live.
  std::unordered_map<LiveTraceId, LiftedFunction *> live_traces;

  // Pointer to the compiled `__vmill_resume`.
  void (*resume_intrinsic)(ArchState *, PC, Memory *, TaskStatus,
                           LiftedFunction *);

  // Pointer to the compiled `__vmill_done`.
  void (*done_intrinsic)(ArchState *, PC, Memory *);

  // Pointer to the compiled `__remill_missing_block`.
  LiftedFunction *missing_block_intrinsic;

  // Pointer to the compiled `__vmill_allocate_state`. This is a runtime
  // function that allocates arch-specific `State` structures.
  ArchState *(*allocate_state_intrinsic)(void);
};

}  // namespace vmill

#endif  // VMILL_EXECUTOR_EXECUTOR_H_
