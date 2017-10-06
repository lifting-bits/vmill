/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cstdint>
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
      active_cache(parent.active_cache),
      cache(parent.cache) {

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

void Context::VisitLiftedModule(llvm::Module *) {}

// Lift code for a task.
llvm::Function *Context::GetLiftedFunctionForTask(const Task &task) {
  if (gLRUAddressSpace->CodeVersionIsInvalid()) {
    active_cache.clear();
  }

  auto code_version = gLRUAddressSpace->CodeVersion();
  LiveTraceId live_id = {task.pc, code_version};
  auto it = active_cache.find(live_id);
  if (it != active_cache.end()) {
    return it->second;
  }

  llvm::Function *ret_func = nullptr;

  // Decode the requested trace, and perhaps way more.
  auto module = std::make_shared<llvm::Module>("", *context);
  auto decoded_traces = DecodeTraces(*gLRUAddressSpace, task.pc);
  for (const auto &trace : decoded_traces) {
    LiftedTraceId lift_id = {trace.entry_pc, trace.hash};
    auto &lifted_func = cache[lift_id];
    if (!lifted_func) {
      lifted_func = lifter->LiftTraceIntoModule(trace, module.get());
    }

    live_id = {task.pc, code_version};
    active_cache[live_id] = lifted_func;

    if (trace.entry_pc == task.pc) {
      ret_func = lifted_func;
    }
  }

  VisitLiftedModule(module.get());
  modules.emplace_back(std::move(module));

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
