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

static thread_local Executor *gExecutor = nullptr;
static thread_local bool gFaulted = false;
static thread_local uint64_t gFaultAddress = 0;

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

extern "C" void *__vmill_schedule(ArchState *state, PC pc,
                                  AddressSpace *memory,
                                  TaskStatus status) {
  Task task = {state, pc, memory, status};
  gExecutor->EnqueueTask(task);
  return nullptr;
}

#define MAKE_MEM_READ(ret_type, read_type, suffix, read_size) \
    extern "C" ret_type __remill_read_memory_ ## suffix( \
        AddressSpace *memory, uint64_t addr) { \
      read_type ret_val = 0; \
      if (likely(memory->TryRead(addr, &ret_val))) { \
        return ret_val; \
      } else { \
        if (!gFaulted) { \
          gFaultAddress = addr; \
        } \
        gFaulted = true; \
        return 0; \
      } \
    }

MAKE_MEM_READ(uint8_t, uint8_t, 8, 1)
MAKE_MEM_READ(uint16_t, uint16_t, 16, 2)
MAKE_MEM_READ(uint32_t, uint32_t, 32, 4)
MAKE_MEM_READ(uint64_t, uint64_t, 64, 8)
MAKE_MEM_READ(float, float, f32, 4)
MAKE_MEM_READ(double, double, f64, 8)

#undef MAKE_MEM_READ

extern "C" double __remill_read_memory_f80(
    AddressSpace *memory, uint64_t addr) {
  uint8_t data[sizeof(long double)] = {};
  if (memory->TryRead(addr, data, 10)) {
    return static_cast<double>(*reinterpret_cast<long double *>(data));
  } else {
    if (!gFaulted) {
      gFaultAddress = addr;
    }
    gFaulted = true;
    return 0.0;
  }
}

#define MAKE_MEM_WRITE(input_type, write_type, suffix, write_size) \
    extern "C" AddressSpace *__remill_write_memory_ ## suffix( \
        AddressSpace *memory, uint64_t addr, input_type val) { \
      if (unlikely(!memory->TryWrite(addr, val))) { \
        if (!gFaulted) { \
          gFaultAddress = addr; \
        } \
        gFaulted = true; \
      } \
      return memory; \
    }

MAKE_MEM_WRITE(uint8_t, uint8_t, 8, 1)
MAKE_MEM_WRITE(uint16_t, uint16_t, 16, 2)
MAKE_MEM_WRITE(uint32_t, uint32_t, 32, 4)
MAKE_MEM_WRITE(uint64_t, uint64_t, 64, 8)
MAKE_MEM_WRITE(float, float, f32, 4)
MAKE_MEM_WRITE(double, double, f64, 8)

#undef MAKE_MEM_WRITE

extern "C" AddressSpace *__remill_write_memory_f80(
    AddressSpace *memory, uint64_t addr, double val) {
  auto long_val = static_cast<long double>(val);
  if (unlikely(!memory->TryWrite(addr, &long_val, 10))) {
    if (!gFaulted) {
      gFaultAddress = addr;
    }
    gFaulted = true;
  }
  return memory;
}

}  // namespace

TaskQueue::TaskQueue(void)
    : has_next_task(false),
      next_task{},
      queue() {}

void TaskQueue::Enqueue(const Task &task) {
  if (queue.empty() && !has_next_task) {
    next_task = task;
    has_next_task = true;
  } else {
    queue.push_back(task);
  }
}

bool TaskQueue::TryDequeue(Task *task_out) {
  bool ret = false;
  if (has_next_task) {
    has_next_task = false;
    ret = true;

  } else if (!queue.empty()) {
    next_task = queue.front();
    queue.pop_front();
    ret = true;
  }

  if (task_out) {
    *task_out = next_task;
  }

  return ret;
}

Executor::Executor(void)
    : context(new llvm::LLVMContext),
      lifter(Lifter::Create(context)),
      code_cache(CodeCache::Create(context)),
      resume_intrinsic(reinterpret_cast<decltype(resume_intrinsic)>(
          code_cache->Lookup("__vmill_resume"))),
      done_intrinsic(reinterpret_cast<decltype(done_intrinsic)>(
          code_cache->Lookup("__vmill_done"))),
      missing_block_intrinsic(reinterpret_cast<LiftedFunction *>(
          code_cache->Lookup("__remill_missing_block"))),
      allocate_state_intrinsic(
          reinterpret_cast<decltype(allocate_state_intrinsic)>(
              code_cache->Lookup("__vmill_allocate_state"))) {

  CHECK(resume_intrinsic != nullptr)
      << "Could not locate __vmill_resume.";

  CHECK(done_intrinsic != nullptr)
      << "Could not locate __vmill_done";

  CHECK(missing_block_intrinsic != nullptr)
      << "Could not locate __remill_missing_block";

  CHECK(allocate_state_intrinsic != nullptr)
      << "Could not locate __vmill_allocate_state";
}

void Executor::DecodeTracesFromTask(const Task &task) {
  auto code_version = task.memory->ComputeCodeVersion();
  auto seen_task_pc = false;
  auto traces = DecodeTraces(*task.memory, task.pc);
  auto trace_it = traces.begin();
  while (trace_it != traces.end()) {
    auto it = trace_it;
    ++trace_it;

    auto trace_id = it->id;
    auto trace_pc = it->pc;
    seen_task_pc = seen_task_pc || trace_pc == task.pc;

    LiveTraceId live_id = {trace_pc, code_version};
    auto &handler = live_traces[live_id];

    // Already lifted and in our live cache.
    if (handler) {
      traces.erase(it);
      continue;
    }

    // Already lifted, but not in our live cache.
    auto lifted_func = code_cache->Lookup(trace_id);
    if (lifted_func) {
      handler = lifted_func;
      traces.erase(it);
      continue;
    }

    // Make sure every trace block has a presence in the cache.
    handler = missing_block_intrinsic;
  }

  LOG_IF(ERROR, !seen_task_pc)
      << "Decoded trace list does not include originally requested PC "
      << std::hex << static_cast<uint64_t>(task.pc);

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
}

void Executor::Execute(void) {
  Task task;
  while (task_queue.TryDequeue(&task)) {
    Execute(task);
  }
}

void Executor::Execute(const Task &task) {
  if (unlikely(task.memory->CodeVersionIsInvalid())) {
    LOG(INFO)
        << "Clearing live trace cache due to code version change.";
    live_traces.clear();
  }

  LiveTraceId live_id = {task.pc, task.memory->ComputeCodeVersion()};
  auto live_id_it = live_traces.find(live_id);

  if (unlikely(live_id_it == live_traces.end())) {
    DecodeTracesFromTask(task);
    live_id_it = live_traces.find(live_id);
    CHECK(live_id_it != live_traces.end())
        << "Could not locate lifted function for " << std::hex
        << static_cast<uint64_t>(task.pc) << std::dec;
  }

  gExecutor = this;
  gFaulted = false;
  resume_intrinsic(task.state, task.pc, task.memory,
                   task.status, live_id_it->second);

  if (unlikely(gFaulted)) {
    LOG(ERROR)
        << "Executing faulted accessing address " << std::hex << gFaultAddress;
  }

  gExecutor = nullptr;
  gFaulted = false;
  gFaultAddress = 0;
}

void Executor::AddInitialTask(const std::string &state_bytes, PC pc,
                              AddressSpace *memory) {
  gExecutor = this;
  gFaulted = false;
  auto state = allocate_state_intrinsic();

  LOG_IF(ERROR, gFaulted)
      << "Executing faulted accessing address " << std::hex << gFaultAddress
      << std::dec << "while allocating a task register state.";

  gExecutor = nullptr;
  gFaulted = false;

  memcpy(state, state_bytes.data(), state_bytes.size());
  Task task{state, pc, memory, kTaskStoppedAtSnapshotEntryPoint};
  EnqueueTask(task);
}

void Executor::EnqueueTask(const Task &task) {
  if (!gFaulted) {
    task_queue.Enqueue(task);
  } else {
    done_intrinsic(task.state, task.pc, task.memory);
  }
}

}  // namespace vmill
