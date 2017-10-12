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

#ifndef VMILL_CONTEXT_CONTEXT_H_
#define VMILL_CONTEXT_CONTEXT_H_

#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "vmill/Arch/Decoder.h"
#include "vmill/BC/Lifter.h"
#include "vmill/Runtime/TaskStatus.h"
#include "vmill/Util/Hash.h"

namespace llvm {
class LLVMContext;
}  // namespace llvm
namespace vmill {

class AddressSpace;
class Context;
class Executor;

using ContextPtr = std::unique_ptr<Context>;

// A task is like a thread, but really, it's the runtime that gives a bit more
// meaning to threads. The runtime has `resume`, `pause`, `stop`, and `schedule`
// intrinsics. When
struct Task {
 public:
  void *state;
  uint64_t pc;
  void *memory;
  TaskStatus status;
};

struct LiveTraceId {
 public:
  uint64_t pc;  // Entry PC of the trace.
  uint64_t hash;  // Hash of all executable memory.

  inline bool operator==(const LiveTraceId &that) const {
    return pc == that.pc && hash == that.hash;
  }
};

}  // namespace vmill

VMILL_MAKE_STD_HASH_OVERRIDE(vmill::TraceId)
VMILL_MAKE_STD_HASH_OVERRIDE(vmill::LiveTraceId)

namespace vmill {

// An execution context. An execution context can contain the state of one or
// more emulated tasks.
class Context {
 public:
  virtual ~Context(void);

  Context(void);

  // Creates a new address space, and returns an opaque handle to it.
  void *CreateAddressSpace(void);

  // Clones an existing address space, and returns an opaque handle to the
  // clone.
  void *CloneAddressSpace(void *);

  // Destroys an address space. This doesn't actually free the underlying
  // address space. Instead it clears it out so that all future operations
  // fail.
  void DestroyAddressSpace(void *);

  // Returns a pointer to the address space associated with a memory handle.
  AddressSpace *AddressSpaceOf(void *) const;

  void CreateInitialTask(const std::string &state, uint64_t pc, void *memory);

  bool TryExecuteNextTask(void);

  void ScheduleTask(const Task &task);

  static Context *gCurrent;
  static AddressSpace *gLRUAddressSpace;
  static void *gLRUMemory;
  static void *gLRUState;

 protected:
  void LoadLiftedModule(const std::shared_ptr<llvm::Module> &module);

  virtual void SaveLiftedModule(const std::shared_ptr<llvm::Module> &module);

  // LLVM context shared by all modules so that we can easily share LLVM types
  // and constants across the modules.
  std::shared_ptr<llvm::LLVMContext> context;

 private:
  friend class Executor;

  Context(const Context &) = delete;
  Context(const Context &&) = delete;
  Context &operator=(Context &) = delete;
  Context &operator=(Context &&) = delete;

  // Lift code for a task.
  llvm::Function *GetLiftedFunctionForTask(const Task &task);

  // List of all address spaces.
  std::vector<AddressSpace *> address_spaces;

  // Shared instruction lifter.
  std::shared_ptr<Lifter> lifter;

  // Shared instruction executor, so that compiled code is shared across
  // contexts.
  std::unique_ptr<Executor> executor;

  // List of tasks available for scheduling.
  std::list<Task> tasks;

  // List of all lifted modules. Each module may have one or more lifted
  // traces.
  std::list<std::shared_ptr<llvm::Module>> modules;

  // Cache mapping active traces to their LLVM functions. This cache is
  // invalidated any time executable code is modified, removed, or created.
  std::unordered_map<LiveTraceId, llvm::Function *> live_trace_cache;

  // The full cache, mapping traces to their LLVM functions.
  std::unordered_map<TraceId, llvm::Function *> trace_cache;
};

using ContextPtr = std::unique_ptr<Context>;

}  // namespace vmill

#endif  // VMILL_CONTEXT_CONTEXT_H_
