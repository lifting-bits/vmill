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
#include <cfenv>

struct ArchState;
struct Memory;

namespace vmill {

class AddressSpace;

enum class PC : uint64_t;

enum TaskStatus {
  kTaskStatusRunnable,

  // An error occurred while accessing memory while this task was executing.
  // We can only really handle these out of band, and the info about the
  // error is located in `Task::mem_access_fault`.
  kTaskStatusMemoryAccessFault,

  kTaskStatusError,
  kTaskStopped,
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
  kTaskExited
};

enum MemoryAccessFaultKind {
  kMemoryAccessNoFault,
  kMemoryAccessFaultOnRead,
  kMemoryAccessFaultOnWrite,
  kMemoryAccessFaultOnExecute
};

enum MemoryValueType {
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

  // Status information.
  TaskStatus status;
  TaskStopLocation location;

  // Floating point environment of this task; this is to let us resume in this
  // task with the correct rounding modes and such.
  fenv_t floating_point_env;

  struct {
    MemoryAccessFaultKind kind;
    MemoryValueType value_type;
    unsigned access_size;  // In bytes.
    uint64_t address;
  } mem_access_fault;
};

}  // namespace vmill

#endif  // VMILL_RUNTIME_TASKSTATUS_H_
