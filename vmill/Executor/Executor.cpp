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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cfenv>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"
#include "vmill/Arch/Arch.h"
#include "vmill/Arch/Decoder.h"
#include "vmill/BC/Lifter.h"
#include "vmill/BC/Util.h"
#include "vmill/Executor/CodeCache.h"
#include "vmill/Executor/Executor.h"
#include "vmill/Program/AddressSpace.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Workspace/Workspace.h"

DEFINE_uint64(num_io_threads, std::thread::hardware_concurrency(),
              "Number of I/O threads.");

namespace vmill {
namespace {

static thread_local Task *gTask = nullptr;
static thread_local Executor *gExecutor = nullptr;

static const char *AccessKindToString(MemoryAccessFaultKind kind) {
  switch (kind) {
    case kMemoryAccessNoFault:
      return "none";
    case kMemoryAccessFaultOnRead:
      return "read";
    case kMemoryAccessFaultOnWrite:
      return "write";
    case kMemoryAccessFaultOnExecute:
      return "execute";
  }
}

__attribute__((noinline))
static void LogFault(std::ostream &os, Task *task) {
  const auto memory = task->memory;
  const auto pc_uint = static_cast<uint64_t>(task->last_pc);
  const auto &fault = task->mem_access_fault;
  os
      << "Task faulted while executing trace " << std::hex
      << pc_uint << " (" << memory->ToVirtualAddress(pc_uint) << ")"
      << std::dec << " when trying to " << AccessKindToString(fault.kind)
      << " " << fault.access_size << " bytes of memory from "
      << std::hex << fault.address << std::dec << std::endl;
}

extern "C" {

// Returns a pointer to the currently executing task.
Task *__vmill_current(void) {
  return gTask;
}

AddressSpace *__vmill_allocate_address_space(void) {
  return new AddressSpace;
}

void __vmill_free_address_space(AddressSpace *memory) {
  delete memory;
}

bool __vmill_can_read_byte(AddressSpace *memory, uint64_t addr) {
  return memory->CanRead(addr);
}

bool __vmill_can_write_byte(AddressSpace *memory, uint64_t addr) {
  return memory->CanWrite(addr);
}

AddressSpace *__vmill_allocate_memory(
    AddressSpace *memory, uint64_t where, uint64_t size,
    const char *name, uint64_t offset) {
  memory->AddMap(where, size, name, offset);
  return memory;
}

AddressSpace *__vmill_free_memory(
    AddressSpace *memory, uint64_t where, uint64_t size) {
  memory->RemoveMap(where, size);
  return memory;
}

AddressSpace *__vmill_protect_memory(
    AddressSpace *memory, uint64_t where, uint64_t size, bool can_read,
    bool can_write, bool can_exec) {
  memory->SetPermissions(where, size, can_read, can_write, can_exec);
  return memory;
}

// Returns `true` iff a given page is mapped (independent of permissions).
bool __vmill_is_mapped_address(AddressSpace *memory, uint64_t where) {
  return memory->IsMapped(where);
}

// Finds some unmapped memory.
uint64_t __vmill_find_unmapped_address(
    AddressSpace *memory, uint64_t base, uint64_t limit, uint64_t size) {
  uint64_t hole = 0;
  if (memory->FindHole(base, limit, size, &hole)) {
    return hole;
  } else {
    return 0;
  }
}

#define MAKE_MEM_READ(ret_type, read_type, suffix, read_size, vtype) \
    ret_type __remill_read_memory_ ## suffix( \
        AddressSpace *memory, uint64_t addr) { \
      read_type ret_val = 0; \
      if (likely(memory->TryRead(addr, &ret_val))) { \
        return ret_val; \
      } else { \
        if (likely(gTask != nullptr)) { \
          auto &fault = gTask->mem_access_fault; \
          if (kMemoryAccessNoFault == fault.kind) { \
            fault.kind = kMemoryAccessFaultOnRead; \
            fault.value_type = vtype; \
            fault.access_size = read_size; \
            fault.address = addr; \
          } \
        } \
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

double __remill_read_memory_f80(
    AddressSpace *memory, uint64_t addr) {
  uint8_t data[sizeof(long double)] = {};
  if (memory->TryRead(addr, data, 10)) {
    return static_cast<double>(*reinterpret_cast<long double *>(data));
  } else {
    if (likely(gTask != nullptr)) {
      auto &fault = gTask->mem_access_fault;
      if (kMemoryAccessNoFault == fault.kind) {
        fault.kind = kMemoryAccessFaultOnRead;
        fault.value_type = kMemoryValueTypeFloatingPoint;
        fault.access_size = 10;
        fault.address = addr;
      }
    }
    return 0.0;
  }
}

#define MAKE_MEM_WRITE(input_type, write_type, suffix, write_size, vtype) \
    AddressSpace *__remill_write_memory_ ## suffix( \
        AddressSpace *memory, uint64_t addr, input_type val) { \
      if (unlikely(!memory->TryWrite(addr, val))) { \
        if (likely(gTask != nullptr)) { \
          auto &fault = gTask->mem_access_fault; \
          if (kMemoryAccessNoFault == fault.kind) { \
            fault.kind = kMemoryAccessFaultOnWrite; \
            fault.value_type = vtype; \
            fault.access_size = write_size; \
            fault.address = addr; \
          } \
        } \
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

AddressSpace *__remill_write_memory_f80(
    AddressSpace *memory, uint64_t addr, double val) {
  auto long_val = static_cast<long double>(val);
  if (unlikely(!memory->TryWrite(addr, &long_val, 10))) {
    if (likely(gTask != nullptr)) {
      auto &fault = gTask->mem_access_fault;
      if (kMemoryAccessNoFault == fault.kind) {
        fault.kind = kMemoryAccessFaultOnWrite;
        fault.value_type = kMemoryValueTypeFloatingPoint;
        fault.access_size = 10;
        fault.address = addr;
      }
    }
  }
  return memory;
}

void __vmill_set_location(PC pc, vmill::TaskStopLocation loc) {
  gTask->pc = pc;
  gTask->location = loc;
  switch (loc) {
    case kTaskStoppedAtError:
    case kTaskStoppedBeforeUnhandledHyperCall:
      gTask->status = kTaskStatusError;
      break;
    case kTaskStoppedAtExit:
      gTask->status = kTaskStatusExited;
      break;

    default:
      break;
  }
}

Memory *__remill_error(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtError;
  gTask->status = kTaskStatusError;
  return memory;
}

Memory *__remill_missing_block(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtError;
  gTask->status = kTaskStatusError;
  return memory;
}

Memory *__remill_jump(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtJumpTarget;
  return memory;
}

Memory *__remill_function_call(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtCallTarget;
  return memory;
}

Memory *__remill_function_return(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtReturnTarget;
  return memory;
}

uint8_t __remill_undefined_8(void) {
  return 0;
}

uint16_t __remill_undefined_16(void) {
  return 0;
}

uint32_t __remill_undefined_32(void) {
  return 0;
}

uint64_t __remill_undefined_64(void) {
  return 0;
}

float __remill_undefined_f32(void) {
  return 0.0;
}

double __remill_undefined_f64(void) {
  return 0.0;
}

// Memory barriers types, see: http://g.oswego.edu/dl/jmm/cookbook.html
Memory *__remill_barrier_load_load(Memory * memory) {
  return memory;
}

Memory *__remill_barrier_load_store(Memory * memory) {
  return memory;
}

Memory *__remill_barrier_store_load(Memory * memory) {
  return memory;
}

Memory *__remill_barrier_store_store(Memory * memory) {
  return memory;
}

// Atomic operations. The address/size are hints, but the granularity of the
// access can be bigger. These have implicit StoreLoad semantics.
Memory *__remill_atomic_begin(Memory * memory) {
  return memory;
}

Memory *__remill_atomic_end(Memory * memory) {
  return memory;
}

int __remill_fpu_exception_test_and_clear(int read_mask, int clear_mask) {

  auto except = std::fetestexcept(read_mask);
  std::feclearexcept(clear_mask);
  return except;
}

extern void __vmill_execute_on_stack(Task *, LiftedFunction *, Stack *);

void __vmill_execute(Task *task, LiftedFunction *lifted_func) {
  const auto memory = task->memory;
  const auto pc = task->pc;
  auto &task_fp_env = task->floating_point_env;

  fenv_t native_fp_env = {};
  fegetenv(&native_fp_env);
  fesetenv(&task_fp_env);
  lifted_func(task->state, pc, memory);
  fegetenv(&task_fp_env);
  fesetenv(&native_fp_env);

  task->last_pc = pc;

  const auto &fault = task->mem_access_fault;
  if (kMemoryAccessNoFault == fault.kind) {
    switch (task->location) {
      case kTaskStoppedAtError:
      case kTaskStoppedBeforeUnhandledHyperCall:
        task->status = kTaskStatusError;
        break;
      default:
        task->status = kTaskStatusRunnable;
        break;
    }

  } else {
    LogFault(LOG(ERROR), task);
    LogRegisterState(LOG(ERROR), task->state);
    memory->LogMaps(LOG(ERROR));
    task->status = kTaskStatusError;
  }
}

// Called by the runtime to execute some lifted code.
void __vmill_run(Task *task) {
  CHECK(!task->must_be_zero);

  gTask = task;

  // The task is waiting for an asynchronous operation to complete.
  if (unlikely(kTaskStatusResumable == task->status)) {
    longjmp(task->resume_context, 1);
  }

  CHECK(kTaskStatusRunnable == task->status);

  const auto lifted_func = gExecutor->FindLiftedFunctionForTask(task);

  if (!FLAGS_num_io_threads) {
    __vmill_execute(task, lifted_func);

  } else {
    __vmill_execute_on_stack(task, lifted_func, &(task->async_stack[1]));
  }

  CHECK(!task->must_be_zero);

  gTask = nullptr;
}

}  // extern "C"
}  // namespace

Executor::Executor(void)
    : context(new llvm::LLVMContext),
      lifter(Lifter::Create(context)),
      code_cache(CodeCache::Create(context)),
      has_run(false),
      will_run_many(false),
      async_io_workers(FLAGS_num_io_threads),
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
    auto last_pc = static_cast<uint64_t>(task->last_pc);
    LOG(ERROR)
        << "Cannot execute non-executable code at "
        << std::hex << task_pc_uint << ". Last trace entry PC was "
        << last_pc << " (" << memory->ToVirtualAddress(last_pc)
        << ")."<< std::dec;

    LogRegisterState(LOG(ERROR), task->state);
    memory->LogMaps(LOG(ERROR));

    task->status = kTaskStatusError;
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

    LogRegisterState(LOG(ERROR), task->state);
    memory->LogMaps(LOG(ERROR));
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
