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
#include <setjmp.h>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

#include "vmill/Arch/Arch.h"
#include "vmill/Arch/Decoder.h"
#include "vmill/BC/Lifter.h"
#include "vmill/BC/Util.h"
#include "vmill/Executor/AsyncIO.h"
#include "vmill/Executor/CodeCache.h"
#include "vmill/Executor/Coroutine.h"
#include "vmill/Executor/Executor.h"
#include "vmill/Program/AddressSpace.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Workspace/Tool.h"
#include "vmill/Workspace/Workspace.h"

DECLARE_uint64(num_io_threads);
DECLARE_string(tool);

namespace vmill {

thread_local Executor *gExecutor = nullptr;

namespace {

// Load the instrumentation tool that we'll be running.
static std::unique_ptr<Tool> LoadTool(void) {
  auto tool = Tool::Load(FLAGS_tool);
  if (FLAGS_num_io_threads) {
    return std::unique_ptr<Tool>(new AsyncIOTool(std::move(tool)));
  } else {
    return tool;
  }
}

}  // namespace

Executor::Executor(void)
    : context(new llvm::LLVMContext),
      lifter(Lifter::Create(context)),
      code_cache(CodeCache::Create(LoadTool(), context)),
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

  LOG(INFO)
      << "Resuming snapshotted execution.";
  resume_intrinsic();

  LOG(INFO)
      << "Finalizing the runtime.";
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
