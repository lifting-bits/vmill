/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cstdint>

#include <llvm/IR/LLVMContext.h>

#include "vmill/BC/Executor.h"
#include "vmill/BC/Lifter.h"
#include "vmill/Context/Context.h"
#include "vmill/Context/AddressSpace.h"

namespace vmill {
namespace {

static __thread Context *gCurrentContext = nullptr;

extern "C" bool __vmill_can_read_byte(void *memory, uint64_t addr) {
  return gCurrentContext->AddressSpaceOf(memory)->CanRead(addr);
}

extern "C" bool __vmill_can_write_byte(void *memory, uint64_t addr) {
  return gCurrentContext->AddressSpaceOf(memory)->CanWrite(addr);
}

extern "C" void *__vmill_allocate_memory(void *memory, uint64_t where,
                                         uint64_t size) {
  auto addr_space = gCurrentContext->AddressSpaceOf(memory);
  addr_space->AddMap(where, size);
  return memory;
}

extern "C" void *__vmill_free_memory(void *memory, uint64_t where, uint64_t size) {
  auto addr_space = gCurrentContext->AddressSpaceOf(memory);
  addr_space->RemoveMap(where, size);
  return memory;
}

extern "C" void *__vmill_protect_memory(void *memory, uint64_t where,
                                        uint64_t size, bool can_read,
                                        bool can_write, bool can_exec) {
  auto addr_space = gCurrentContext->AddressSpaceOf(memory);
  addr_space->SetPermissions(where, size, can_read, can_write, can_exec);
  return memory;
}

extern "C" uint64_t __vmill_next_memory_end(Memory *memory, uint64_t where) {
  auto addr_space = gCurrentContext->AddressSpaceOf(memory);
  uint64_t nearest_end = 0;
  if (addr_space->NearestLimitAddress(where, &nearest_end)) {
    return nearest_end;
  } else {
    return 0;
  }
}

extern "C" uint64_t __vmill_prev_memory_begin(Memory *memory, uint64_t where) {
  auto addr_space = gCurrentContext->AddressSpaceOf(memory);
  uint64_t nearest_begin = 0;
  if (addr_space->NearestBaseAddress(where, &nearest_begin)) {
    return nearest_begin;
  } else {
    return 0;
  }
}

}  // namespace

std::unique_ptr<Context> Context::Create(void) {
  return std::unique_ptr<Context>(new Context);
}

std::unique_ptr<Context> Context::Clone(const std::unique_ptr<Context> &that) {
  return std::unique_ptr<Context>(new Context(*that));
}

Context::Context(void)
    : context(new llvm::LLVMContext),
      lifter(vmill::Lifter::Create(context)),
      executor(vmill::Executor::GetNativeExecutor(context)) {}

Context::Context(const Context &parent)
    : lifter(parent.lifter),
      executor(parent.executor) {

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
  auto id = reinterpret_cast<uintptr_t>(handle);
  CHECK(id < address_spaces.size())
      << "Cannot clone non-existent address space " << id;

  auto addr_space = address_spaces[id];
  LOG_IF(ERROR, addr_space->IsDead())
      << "Killing already dead address space " << id;
  addr_space->Kill();
}

AddressSpace *Context::AddressSpaceOf(void *handle) {
  auto id = reinterpret_cast<uintptr_t>(handle);
  CHECK(id < address_spaces.size())
      << "Cannot clone non-existent address space " << id;
  return address_spaces[id];
}

// Call into the runtime to allocate a `State` structure, and fill it with
// the bytes from `data`.
void *Context::AllocateStateInRuntime(const std::string &data) {
  return executor->AllocateStateInRuntime(data);
}

void Context::ScheduleTask(const Task &task) {
  tasks.push_back(task);
}

bool Context::TryDequeueTask(Task *task_out) {
  if (tasks.empty()) {
    return false;
  } else {
    *task_out = tasks.front();
    tasks.pop_front();
    return true;
  }
}

void Context::ResumeTask(const Task &task) {
  gCurrentContext = this;
}

}  // namespace vmill
