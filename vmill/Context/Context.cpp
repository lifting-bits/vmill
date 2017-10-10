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
#include "vmill/Context/AddressSpace.h"

namespace vmill {

Context *Context::gCurrent = nullptr;
AddressSpace *Context::gLRUAddressSpace = nullptr;
void *Context::gLRUMemory = nullptr;
void *Context::gLRUState = nullptr;

Context::Context(void)
    : context(new llvm::LLVMContext),
      lifter(vmill::Lifter::Create(context)),
      executor(vmill::Executor::GetNativeExecutor(context)) {

  auto dead_space = new AddressSpace;
  dead_space->Kill();
  address_spaces.push_back(dead_space);
}

Context::Context(const Context &parent)
    : context(parent.context),
      lifter(parent.lifter),
      executor(parent.executor),
      tasks(parent.tasks),
      modules(parent.modules),
      live_trace_cache(parent.live_trace_cache),
      lifted_trace_cache(parent.lifted_trace_cache) {

  address_spaces.reserve(parent.address_spaces.size());
  for (auto space : parent.address_spaces) {
    address_spaces.push_back(new AddressSpace(*space));
  }
}

Context::~Context(void) {
  for (auto space : address_spaces) {
    if (space) {
      delete space;
    }
  }
}

// Creates a new address space, and returns an opaque handle to it.
void *Context::CreateAddressSpace(void) {
  auto id = address_spaces.size();
  address_spaces.push_back(new AddressSpace);
  return reinterpret_cast<void *>(id);
}

// Clones an existing address space, and returns an opaque handle to the
// clone.
void *Context::CloneAddressSpace(void *handle) {
  auto parent_id = reinterpret_cast<uintptr_t>(handle);
  CHECK(parent_id < address_spaces.size())
      << "Cannot clone non-existent address space " << parent_id;

  auto parent = address_spaces[parent_id];
  auto id = address_spaces.size();
  address_spaces.push_back(new AddressSpace(*parent));
  return reinterpret_cast<void *>(id);
}

// Destroys an address space.
void Context::DestroyAddressSpace(void *handle) {
  if (handle == gLRUMemory) {
    gLRUMemory = nullptr;
    gLRUAddressSpace = nullptr;
  }

  auto id = reinterpret_cast<uintptr_t>(handle);
  CHECK(id < address_spaces.size())
      << "Cannot clone non-existent address space " << id;

  auto addr_space = address_spaces[id];
  LOG_IF(ERROR, addr_space->IsDead())
      << "Killing already dead address space " << id;
  addr_space->Kill();
}

AddressSpace *Context::AddressSpaceOf(void *handle) const {
  if (handle == gLRUMemory) {
    return gLRUAddressSpace;
  } else {
    auto id = reinterpret_cast<uintptr_t>(handle);
    CHECK(id < address_spaces.size())
        << "Cannot clone non-existent address space " << id;
    gLRUMemory = handle;
    gLRUAddressSpace = address_spaces[id];
    return gLRUAddressSpace;
  }
}

void Context::CreateInitialTask(const std::string &state,
                                uint64_t pc, void *memory) {
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
    uint64_t pc = 0;
    uint64_t hash = 0;
    auto num_parts = sscanf(name.c_str(), "_%" SCNx64 "_%" SCNx64, &pc, &hash);
    if (2 != num_parts) {
      continue;
    }

    num_traces += 1;
    LiftedTraceId lift_id = {pc, hash};
    lifted_trace_cache[lift_id] = &func;
  }

  LOG(INFO)
      << "Loaded " << std::dec << num_traces
      << " traces from module " << module->getName().str();
}

void Context::SaveLiftedModule(const std::shared_ptr<llvm::Module> &) {}

// Lift code for a task.
llvm::Function *Context::GetLiftedFunctionForTask(const Task &task) {
  if (gLRUAddressSpace->CodeVersionIsInvalid()) {
    LOG(INFO)
        << "Code version is invalid, clearing the active cache";
    live_trace_cache.clear();
  }

  auto code_version = gLRUAddressSpace->CodeVersion();

  LiveTraceId live_id = {task.pc, code_version};
  auto it = live_trace_cache.find(live_id);
  if (it != live_trace_cache.end()) {
    return it->second;
  }

  llvm::Function *ret_func = nullptr;

  // Decode the requested trace, and perhaps way more.
  auto module = std::make_shared<llvm::Module>("", *context);
  auto decoded_traces = DecodeTraces(*gLRUAddressSpace, task.pc);
  auto num_lifted_traces = 0;
  for (const auto &trace : decoded_traces) {
    LiftedTraceId lift_id = {trace.entry_pc, trace.hash};
    auto &lifted_func = lifted_trace_cache[lift_id];
    if (!lifted_func) {
      num_lifted_traces += 1;
      lifted_func = lifter->LiftTraceIntoModule(trace, module.get());
    }

    live_id = {trace.entry_pc, code_version};
    live_trace_cache[live_id] = lifted_func;

    if (trace.entry_pc == task.pc) {
      ret_func = lifted_func;
    }
  }

  if (num_lifted_traces) {
    LOG(INFO)
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
  gLRUMemory = nullptr;
  gLRUAddressSpace = AddressSpaceOf(task.memory);
  gLRUMemory = task.memory;

  auto func = GetLiftedFunctionForTask(task);
  executor->Execute(task, func);

  gCurrent = nullptr;
  gLRUMemory = nullptr;
  gLRUState = nullptr;
  gLRUAddressSpace = nullptr;

  return true;
}

}  // namespace vmill
