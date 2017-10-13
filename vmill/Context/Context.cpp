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

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>

#include <llvm/IR/Function.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "vmill/Arch/Decoder.h"
#include "vmill/BC/Executor.h"
#include "vmill/BC/Lifter.h"
#include "vmill/Context/Context.h"
#include "vmill/Memory/AddressSpace.h"

namespace vmill {

Context *Context::gCurrent = nullptr;
void *Context::gLRUState = nullptr;
bool Context::gFaulted = false;
uint64_t Context::gFaultAddress = 0;

Context::Context(void)
    : context(new llvm::LLVMContext),
      lifter(vmill::Lifter::Create(context)),
      executor(vmill::Executor::GetNativeExecutor(context)) {}

Context::~Context(void) {}

void Context::CreateInitialTask(const std::string &state,
                                uint64_t pc, AddressSpace *memory) {
  Task task = {executor->AllocateStateInRuntime(state), pc, memory,
               TaskStatus::kTaskStoppedAtSnapshotEntryPoint};
  tasks.push_back(task);
}

void Context::ScheduleTask(const Task &task) {
  tasks.push_back(task);
}

// Load all the lifted functions from an already cached module.
void Context::LoadLiftedModule(const std::shared_ptr<llvm::Module> &module) {
  modules.push_back(module);
  auto num_traces = 0;
  for (auto &func : *module) {
    auto name = func.getName().str();
    TraceId id = {};
    auto num_parts = sscanf(name.c_str(), "_%" SCNx64 "_%" SCNx64,
                            &id.hash1, &id.hash2);
    if (2 == num_parts) {
      num_traces += 1;
      trace_cache[id] = &func;
    }
  }

  DLOG(INFO)
      << "Loaded " << std::dec << num_traces
      << " traces from module " << module->getName().str();
}

void Context::SaveLiftedModule(const std::shared_ptr<llvm::Module> &) {}

// Lift code for a task.
llvm::Function *Context::GetLiftedFunctionForTask(const Task &task) {
  const auto addr_space = task.memory;
  if (addr_space->CodeVersionIsInvalid()) {
    live_trace_cache.clear();
  }

  auto code_version = addr_space->CodeVersion();

  LiveTraceId live_id = {task.pc, code_version};
  auto it = live_trace_cache.find(live_id);
  if (it != live_trace_cache.end()) {
    return it->second;
  }

  llvm::Function *ret_func = nullptr;

  // Decode the requested trace, and perhaps way more.
  std::shared_ptr<llvm::Module> module;
  auto decoded_traces = DecodeTraces(*addr_space, task.pc);
  auto num_lifted_traces = 0;

  for (const auto &trace : decoded_traces) {
    auto &lifted_func = trace_cache[trace.id];
    if (!lifted_func) {
      if (!module) {
        std::stringstream ss;
        ss << std::hex << task.pc << "_at_" << code_version;
        module = std::make_shared<llvm::Module>(ss.str(), *context);
      }
      num_lifted_traces += 1;
      lifted_func = lifter->LiftTraceIntoModule(trace, module.get());
    }

    live_id = {trace.pc, code_version};
    live_trace_cache[live_id] = lifted_func;

    if (trace.pc == task.pc) {
      ret_func = lifted_func;
    }
  }

  if (num_lifted_traces) {
    DLOG(INFO)
        << "Lifted " << std::dec << num_lifted_traces << " of "
        << decoded_traces.size() << " decoded traces";
    SaveLiftedModule(module);
    modules.emplace_back(std::move(module));
  }

  CHECK(ret_func != nullptr);

  return ret_func;
}

bool Context::TryExecuteNextTask(void) {
  if (tasks.empty()) {
    return false;
  }

  auto task = tasks.front();
  tasks.pop_front();

  gCurrent = this;
  gLRUState = task.state;
  gFaulted = false;

  auto func = GetLiftedFunctionForTask(task);
  executor->Execute(task, func);

  if (gFaulted) {
    LOG(ERROR)
        << "Memory access violation while executing in trace "
        << std::hex << task.pc << std::dec;
  }

  gCurrent = nullptr;
  gLRUState = nullptr;

  return true;
}

}  // namespace vmill
