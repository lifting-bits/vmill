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

#include <glog/logging.h>

#include <cfenv>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

#include "vmill/Arch/Decoder.h"
#include "vmill/BC/Lifter.h"
#include "vmill/BC/Util.h"
#include "vmill/Executor/CodeCache.h"
#include "vmill/Executor/Executor.h"
#include "vmill/Program/AddressSpace.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Workspace/Workspace.h"

namespace vmill {
namespace {

static thread_local Task *gTask = nullptr;
static thread_local Executor *gExecutor = nullptr;
static thread_local bool gFaulted = false;

// Returns a pointer to the currently executing task.
extern "C" Task *__vmill_current(void) {
  return gTask;
}

extern "C" AddressSpace *__vmill_allocate_address_space(void) {
  return new AddressSpace;
}

extern "C" void __vmill_free_address_space(AddressSpace *memory) {
  delete memory;
}

extern "C" bool __vmill_can_read_byte(AddressSpace *memory, uint64_t addr) {
  return memory->CanRead(addr);
}

extern "C" bool __vmill_can_write_byte(AddressSpace *memory, uint64_t addr) {
  return memory->CanWrite(addr);
}

extern "C" AddressSpace *__vmill_allocate_memory(
    AddressSpace *memory, uint64_t where, uint64_t size) {
  memory->AddMap(where, size);
  return memory;
}

extern "C" AddressSpace *__vmill_free_memory(
    AddressSpace *memory, uint64_t where, uint64_t size) {
  memory->RemoveMap(where, size);
  return memory;
}

extern "C" AddressSpace *__vmill_protect_memory(
    AddressSpace *memory, uint64_t where, uint64_t size, bool can_read,
    bool can_write, bool can_exec) {
  memory->SetPermissions(where, size, can_read, can_write, can_exec);
  return memory;
}

extern "C" uint64_t __vmill_next_memory_end(
    AddressSpace *memory, uint64_t where) {

  uint64_t nearest_end = 0;
  if (memory->NearestLimitAddress(where, &nearest_end)) {
    return nearest_end;
  } else {
    return 0;
  }
}

extern "C" uint64_t __vmill_prev_memory_begin(
    AddressSpace *memory, uint64_t where) {
  uint64_t nearest_begin = 0;
  if (memory->NearestBaseAddress(where, &nearest_begin)) {
    return nearest_begin;
  } else {
    return 0;
  }
}

#define MAKE_MEM_READ(ret_type, read_type, suffix, read_size, vtype) \
    extern "C" ret_type __remill_read_memory_ ## suffix( \
        AddressSpace *memory, uint64_t addr) { \
      read_type ret_val = 0; \
      if (likely(memory->TryRead(addr, &ret_val))) { \
        return ret_val; \
      } else { \
        if (!gFaulted && gTask) { \
          gTask->mem_access_fault.kind = kMemoryAccessFaultOnRead; \
          gTask->mem_access_fault.value_type = vtype; \
          gTask->mem_access_fault.access_size = read_size; \
          gTask->mem_access_fault.address = addr; \
        } \
        gFaulted = true; \
        return 0; \
      } \
    }

MAKE_MEM_READ(uint8_t, uint8_t, 8, 1, kMemoryValueTypeInteger)
MAKE_MEM_READ(uint16_t, uint16_t, 16, 2, kMemoryValueTypeInteger)
MAKE_MEM_READ(uint32_t, uint32_t, 32, 4, kMemoryValueTypeInteger)
MAKE_MEM_READ(uint64_t, uint64_t, 64, 8, kMemoryValueTypeInteger)
MAKE_MEM_READ(float, float, f32, 4, kMemoryValueTypeFloatingPoint)
MAKE_MEM_READ(double, double, f64, 8, kMemoryValueTypeFloatingPoint)

#undef MAKE_MEM_READ

extern "C" double __remill_read_memory_f80(
    AddressSpace *memory, uint64_t addr) {
  uint8_t data[sizeof(long double)] = {};
  if (memory->TryRead(addr, data, 10)) {
    return static_cast<double>(*reinterpret_cast<long double *>(data));
  } else {
    if (!gFaulted && gTask) {
      gTask->mem_access_fault.kind = kMemoryAccessFaultOnRead;
      gTask->mem_access_fault.value_type = kMemoryValueTypeFloatingPoint;
      gTask->mem_access_fault.access_size = 10;
      gTask->mem_access_fault.address = addr;
    }
    gFaulted = true;
    return 0.0;
  }
}

#define MAKE_MEM_WRITE(input_type, write_type, suffix, write_size, vtype) \
    extern "C" AddressSpace *__remill_write_memory_ ## suffix( \
        AddressSpace *memory, uint64_t addr, input_type val) { \
      if (unlikely(!memory->TryWrite(addr, val))) { \
        if (!gFaulted && gTask) { \
          gTask->mem_access_fault.kind = kMemoryAccessFaultOnWrite; \
          gTask->mem_access_fault.value_type = vtype; \
          gTask->mem_access_fault.access_size = write_size; \
          gTask->mem_access_fault.address = addr; \
        } \
        gFaulted = true; \
      } \
      return memory; \
    }

MAKE_MEM_WRITE(uint8_t, uint8_t, 8, 1, kMemoryValueTypeInteger)
MAKE_MEM_WRITE(uint16_t, uint16_t, 16, 2, kMemoryValueTypeInteger)
MAKE_MEM_WRITE(uint32_t, uint32_t, 32, 4, kMemoryValueTypeInteger)
MAKE_MEM_WRITE(uint64_t, uint64_t, 64, 8, kMemoryValueTypeInteger)
MAKE_MEM_WRITE(float, float, f32, 4, kMemoryValueTypeFloatingPoint)
MAKE_MEM_WRITE(double, double, f64, 8, kMemoryValueTypeFloatingPoint)

#undef MAKE_MEM_WRITE

extern "C" AddressSpace *__remill_write_memory_f80(
    AddressSpace *memory, uint64_t addr, double val) {
  auto long_val = static_cast<long double>(val);
  if (unlikely(!memory->TryWrite(addr, &long_val, 10))) {
    if (!gFaulted && gTask) {
      gTask->mem_access_fault.kind = kMemoryAccessFaultOnRead;
      gTask->mem_access_fault.value_type = kMemoryValueTypeFloatingPoint;
      gTask->mem_access_fault.access_size = 10;
      gTask->mem_access_fault.address = addr;
    }
    gFaulted = true;
  }
  return memory;
}

// Returns `true` if the Task has errored.
static bool TaskStatusIsError(void) {
  switch (gTask->status) {
    case kTaskStatusRunnable:
    case kTaskStopped:
      return false;
    case kTaskStatusMemoryAccessFault:
    case kTaskStatusError:
      return true;
  }
}

extern "C" void __vmill_set_location(PC pc, vmill::TaskStopLocation loc) {
  gTask->pc = pc;
  gTask->location = loc;
  if (!TaskStatusIsError()) {
    switch (loc) {
      case kTaskStoppedAtError:
      case kTaskStoppedBeforeUnhandledHyperCall:
        gTask->status = kTaskStatusError;
        break;
      case kTaskExited:
        gTask->status = kTaskStopped;
        break;

      default:
        break;
    }
  }
}

extern "C" Memory *__remill_error(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtError;
  if (!TaskStatusIsError()) {
    gTask->status = kTaskStatusError;
  }
  return memory;
}

extern "C" Memory *__remill_missing_block(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtError;
  if (!TaskStatusIsError()) {
    gTask->status = kTaskStatusError;
  }
  return memory;
}

extern "C" Memory *__remill_jump(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtJumpTarget;
  return memory;
}

extern "C" Memory *__remill_function_call(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtCallTarget;
  return memory;
}

extern "C" Memory *__remill_function_return(
    ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtReturnTarget;
  return memory;
}


extern "C" uint8_t __remill_undefined_8(void) {
  return 0;
}

extern "C" uint16_t __remill_undefined_16(void) {
  return 0;
}

extern "C" uint32_t __remill_undefined_32(void) {
  return 0;
}

extern "C" uint64_t __remill_undefined_64(void) {
  return 0;
}

extern "C" float __remill_undefined_f32(void) {
  return 0.0;
}

extern "C" double __remill_undefined_f64(void) {
  return 0.0;
}

// Memory barriers types, see: http://g.oswego.edu/dl/jmm/cookbook.html
extern "C" Memory *__remill_barrier_load_load(Memory * memory) {
  return memory;
}

extern "C" Memory *__remill_barrier_load_store(Memory * memory) {
  return memory;
}

extern "C" Memory *__remill_barrier_store_load(Memory * memory) {
  return memory;
}

extern "C" Memory *__remill_barrier_store_store(Memory * memory) {
  return memory;
}

// Atomic operations. The address/size are hints, but the granularity of the
// access can be bigger. These have implicit StoreLoad semantics.
extern "C" Memory *__remill_atomic_begin(Memory * memory) {
  return memory;
}

extern "C" Memory *__remill_atomic_end(Memory * memory) {
  return memory;
}

extern "C" int __remill_fpu_exception_test_and_clear(
    int read_mask, int clear_mask) {

  auto except = std::fetestexcept(read_mask);
  std::feclearexcept(clear_mask);
  return except;
}

// Called by the runtime to execute some lifted code.
extern "C" void __vmill_run(Task *task) {
  gTask = task;

  auto lifted_func = gExecutor->FindLiftedFunctionForTask(task);
  auto pc_uint = static_cast<uint64_t>(task->pc);

  DLOG(INFO)
      << "Executing trace " << std::hex << pc_uint << std::dec;

  fenv_t old_env = {};
  fegetenv(&old_env);
  fesetenv(&(task->floating_point_env));
  lifted_func(task->state, task->pc, task->memory);
  fegetenv(&(task->floating_point_env));
  fesetenv(&old_env);

  gTask = nullptr;

  if (gFaulted) {
    auto memory = task->memory;
    LOG(ERROR)
        << "Task faulted while executing trace " << std::hex
        << pc_uint << " (" << memory->ToVirtualAddress(pc_uint)
        << " lifted to " << reinterpret_cast<void *>(lifted_func)
        << ")" << std::dec;

    gFaulted = false;
    task->status = kTaskStatusMemoryAccessFault;

  } else {
    switch (task->location) {
      case kTaskStoppedAtError:
      case kTaskStoppedBeforeUnhandledHyperCall:
        task->status = kTaskStatusError;
        break;
      default:
        task->status = kTaskStatusRunnable;
        break;
    }
  }
}

}  // namespace

Executor::Executor(void)
    : context(new llvm::LLVMContext),
      lifter(Lifter::Create(context)),
      code_cache(CodeCache::Create(context)),
      has_run(false),
      will_run_many(false),
      init_intrinsic(reinterpret_cast<decltype(init_intrinsic)>(
          code_cache->Lookup("__vmill_init"))),
      create_task_intrinsic(
        reinterpret_cast<decltype(create_task_intrinsic)>(
            code_cache->Lookup("__vmill_create_task"))) ,
      resume_intrinsic(reinterpret_cast<decltype(resume_intrinsic)>(
          code_cache->Lookup("__vmill_resume"))),
      fini_intrinsic(reinterpret_cast<decltype(fini_intrinsic)>(
          code_cache->Lookup("__vmill_fini"))),
      missing_block_intrinsic(reinterpret_cast<LiftedFunction *>(
          code_cache->Lookup("__remill_missing_block"))){

  CHECK(init_intrinsic != nullptr)
      << "Could not locate __vmill_init";

  CHECK(create_task_intrinsic != nullptr)
      << "Could not locate __vmill_create_task";

  CHECK(resume_intrinsic != nullptr)
      << "Could not locate __vmill_resume.";

  CHECK(fini_intrinsic != nullptr)
      << "Could not locate __vmill_fini.";

  CHECK(missing_block_intrinsic != nullptr)
      << "Could not locate __remill_missing_block";
}

void Executor::DecodeTracesFromTask(Task *task) {
  const auto memory = task->memory;
  const auto task_pc = task->pc;
  const auto task_pc_uint = static_cast<uint64_t>(task_pc);
  auto code_version = memory->ComputeCodeVersion();

  DLOG(INFO)
      << "Decoding traces starting from " << std::hex
      << task_pc_uint << " (" << memory->ToVirtualAddress(task_pc_uint)
      << ") for code version " << static_cast<uint64_t>(code_version)
      << std::dec;

  auto seen_task_pc = false;
  auto traces = DecodeTraces(*memory, task_pc);
  auto trace_it = traces.begin();
  while (trace_it != traces.end()) {
    auto it = trace_it;
    ++trace_it;

    auto trace_id = it->id;
    auto trace_pc = it->pc;
    seen_task_pc = seen_task_pc || trace_pc == task_pc;

    LiveTraceId live_id = {trace_pc, code_version};
    auto live_trace_it = live_traces.find(live_id);

    // Already lifted and in our live cache.
    if (live_trace_it != live_traces.end()) {
      traces.erase(it);
      continue;
    }

    // Already lifted, but not in our live cache.
    auto lifted_func = code_cache->Lookup(trace_id);
    if (lifted_func) {
      live_traces[live_id] = lifted_func;
      traces.erase(it);
      continue;
    }
  }

  LOG_IF(ERROR, !seen_task_pc)
      << "Decoded trace list does not include originally requested PC "
      << std::hex << task_pc_uint;

  LiftDecodedTraces(traces);
}

void Executor::LiftDecodedTraces(const DecodedTraceList &traces) {
  auto module = lifter->Lift(traces);
  if (!module) {
    return;
  }

  // Save a copy of the lifted module into the bitcode directory. This is so
  // that other tools can benefit from existing lifted code, but apply their
  // own instrumentation.
  std::stringstream ss;
  ss << Workspace::BitcodeDir() << remill::PathSeparator()
     << remill::ModuleName(module);

  auto file_name = ss.str();
  remill::StoreModuleToFile(module.get(), file_name);

  // TODO(pag): Instrument module.

  code_cache->AddModuleToCache(module);

  // Add the now lifted traces into the live trace cache.
  for (const auto &trace : traces) {
    LiveTraceId live_id = {trace.pc, trace.code_version};
    if (auto lifted_func = code_cache->Lookup(trace.id)) {
      live_traces[live_id] = lifted_func;
    }
  }
}

void Executor::RunOnce(void) {
  CHECK(!has_run)
      << "To emulate process more than once, use `Executor::RunMany`.";

  gExecutor = this;
  will_run_many = false;
  LOG(INFO)
      << "Initializing the runtime.";
  init_intrinsic();

  for (const auto &info : initial_tasks) {
    LOG(INFO)
        << "Creating initial task starting at "
        << std::hex << static_cast<uint64_t>(info.pc) << std::dec;
    create_task_intrinsic(info.state.data(), info.pc, info.memory);
  }
  resume_intrinsic();
  fini_intrinsic();
  gExecutor = nullptr;
  has_run = true;
}

void Executor::RunMany(void) {
  // TODO(pag): Need to make sure that the tasks are created with clones of
  //            the initial address spaces.
  LOG(FATAL)
      << "Executor::RunMany is not yet implemented.";
  gExecutor = this;
  will_run_many = true;

  gExecutor = nullptr;
}

LiftedFunction *Executor::FindLiftedFunctionForTask(Task *task) {
  const auto memory = task->memory;

  // If we're going to repeatedly execut the snapshotted program, then
  // don't clear old versions of the hash table.
  if (unlikely(!will_run_many && memory->CodeVersionIsInvalid())) {
    live_traces.clear();
  }

  const PC task_pc = task->pc;
  const auto task_pc_uint = static_cast<uint64_t>(task_pc);
  const CodeVersion code_version = memory->ComputeCodeVersion();
  const LiveTraceId live_id = {task_pc, code_version};

  auto live_id_it = live_traces.find(live_id);
  if (likely(live_id_it != live_traces.end())) {
    return live_id_it->second;
  }

  // We do a preliminary check here to make sure the code is executable. We
  if (!memory->CanExecute(task_pc_uint)) {
    LOG(ERROR)
        << "Cannot execute non-executable code at"
        << std::hex << task_pc_uint << std::dec;

    task->status = kTaskStatusMemoryAccessFault;
    task->mem_access_fault.kind = kMemoryAccessFaultOnExecute;
    task->mem_access_fault.value_type = kMemoryValueTypeInstruction;
    task->mem_access_fault.access_size = 1;
    task->mem_access_fault.address = static_cast<uint64_t>(task_pc);
    return missing_block_intrinsic;
  }

  DecodeTracesFromTask(task);

  live_id_it = live_traces.find(live_id);
  if (unlikely(live_id_it == live_traces.end())) {
    LOG(ERROR)
        << "Could not locate lifted function for " << std::hex
        << task_pc_uint << std::dec;
    return missing_block_intrinsic;
  }

  return live_id_it->second;
}

void Executor::AddInitialTask(const std::string &state_bytes, PC pc,
                              AddressSpace *memory) {
  InitialTaskInfo info = {state_bytes, pc, memory};
  initial_tasks.push_back(std::move(info));
}

}  // namespace vmill
