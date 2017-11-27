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

#include <memory>
#include <unordered_map>

#include "vmill/BC/Trace.h"
#include "vmill/Etc/ThreadPool/ThreadPool.h"
#include "vmill/Runtime/Task.h"

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

// A compiled lifted trace.
using LiftedFunction = Memory *(ArchState *, PC, Memory *);

struct InitialTaskInfo {
  std::string state;
  PC pc;
  AddressSpace *memory;
};

// Task executor. This manages things like the code cache, and can lift and
// compile code on request.
class Executor {
 public:
  Executor(void);

  void RunOnce(void);
  void RunMany(void);

  void AddInitialTask(const std::string &state, PC pc, AddressSpace *memory);

  LiftedFunction *FindLiftedFunctionForTask(Task *task);

 private:
  __attribute__((noinline))
  void DecodeTracesFromTask(Task *task);

  __attribute__((noinline))
  void LiftDecodedTraces(const DecodedTraceList &traces);

  std::shared_ptr<llvm::LLVMContext> context;
  std::unique_ptr<Lifter> lifter;
  std::unique_ptr<CodeCache> code_cache;

  // Have we previously executed `Executor::Run`?
  bool has_run;
  bool will_run_many;

  // List of async I/O threads. The executor will offload I/O operations of
  // emulated tasks onto these threads.
  ThreadPool async_io_workers;

  // List of initial tasks.
  std::vector<InitialTaskInfo> initial_tasks;

  // Map of "live traces". Instead of mapping PCs to lifted function, we map
  // tuples of (PC, CodeVersion) to lifted functions. These code versions
  // permit multiple address spaces to be simultaneously live.
  std::unordered_map<LiveTraceId, LiftedFunction *> live_traces;

  // Pointer to the compiled `__vmill_init` function. This initializes
  // the OS that is emulated by the runtime.
  void (*init_intrinsic)(void);

  // Pointer to the compiled `__vmill_allocate_state`. This is a runtime
  // function that allocates arch-specific `State` structures.
  void (*create_task_intrinsic)(const void *, PC, AddressSpace *);

  // Pointer to the compiled `__vmill_resume`. This "resumes" execution from
  // where the snapshot left off.
  void (*resume_intrinsic)(void);

  // Pointer to the compiled `__vmill_fini`. This is used to tear down the
  // any remaining things in the OS.
  void (*fini_intrinsic)(void);

  // Pointer to the compiled `__remill_missing_block`.
  LiftedFunction *missing_block_intrinsic;
};

}  // namespace vmill

#endif  // VMILL_EXECUTOR_EXECUTOR_H_
