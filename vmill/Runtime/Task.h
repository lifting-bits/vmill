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

#ifndef VMILL_RUNTIME_TASKSTATUS_H_
#define VMILL_RUNTIME_TASKSTATUS_H_

#include <cstdint>

struct ArchState;
struct Memory;

namespace vmill {

class AddressSpace;
class Coroutine;

enum class PC : uint64_t;

enum TaskStatus : uint64_t {
  // This task is ready to run.
  kTaskStatusRunnable,

  // This task is paused doing async I/O. This is a runnable state.
  kTaskStatusResumable,

  // This task encountered an error.
  kTaskStatusError,

  // This task exited.
  kTaskStatusExited,
};

enum TaskStopLocation {
  kTaskNotYetStarted,
  kTaskStoppedAtSnapshotEntryPoint,
  kTaskStoppedAtJumpTarget,
  kTaskStoppedAtCallTarget,
  kTaskStoppedAtReturnTarget,
  kTaskStoppedAtError,
  kTaskStoppedAfterHyperCall,
  kTaskStoppedBeforeUnhandledHyperCall,
  kTaskStoppedAtExit
};

enum MemoryAccessFaultKind : uint16_t {
  kMemoryAccessNoFault,
  kMemoryAccessFaultOnRead,
  kMemoryAccessFaultOnWrite,
  kMemoryAccessFaultOnExecute
};

enum MemoryValueType : uint16_t {
  kMemoryValueTypeInvalid,
  kMemoryValueTypeInteger,
  kMemoryValueTypeFloatingPoint,
  kMemoryValueTypeInstruction
};

// A task is like a thread, but really, it's the runtime that gives a bit more
// meaning to threads. The runtime has `resume`, `pause`, `stop`, and `schedule`
// intrinsics. When
struct Task {
 public:
  // Register state of this task.
  ArchState *state;

  // Current program counter of this task.
  PC pc;

  // Memory that this task can access.
  AddressSpace *memory;

  // The stack on which lifted code of this task will execute.
  Coroutine *async_routine;

  // Status information.
  TaskStatus status;
  TaskStatus status_on_resume;

  // Where was this task last?
  TaskStopLocation location;

  // Last trace entry program counter executed from this task. This can be
  // a useful debugging aid.
  PC last_pc;

  // Information about the first fault encountered while executing.
  struct {
    uint64_t address;
    uint32_t access_size;  // In bytes.
    MemoryAccessFaultKind kind;
    MemoryValueType value_type;
  } mem_access_fault;

  int32_t fpu_rounding_mode;
  int32_t _padding;
};

}  // namespace vmill

#endif  // VMILL_RUNTIME_TASKSTATUS_H_
