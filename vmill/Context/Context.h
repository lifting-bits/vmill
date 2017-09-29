/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef VMILL_CONTEXT_CONTEXT_H_
#define VMILL_CONTEXT_CONTEXT_H_

#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include "vmill/BC/Executor.h"

namespace llvm {
class LLVMContext;
}  // namespace llvm
namespace vmill {

class AddressSpace;
class Context;
class Lifter;

using ContextPtr = std::unique_ptr<Context>;

// A task is like a thread, but really, it's the runtime that gives a bit more
// meaning to threads. The runtime has `resume`, `pause`, `stop`, and `schedule`
// intrinsics. When
struct Task {
  void *state;
  uint64_t pc;
  void *memory;
};

// An execution context. An execution context can contain the state of one or
// more emulated tasks.
class Context {
 public:
  static ContextPtr Create(void);
  static ContextPtr Clone(const ContextPtr &);

  ~Context(void);

  // Creates a new address space, and returns an opaque handle to it.
  void *CreateAddressSpace(void);

  // Clones an existing address space, and returns an opaque handle to the
  // clone.
  void *CloneAddressSpace(void *);

  // Destroys an address space. This doesn't actually free the underlying
  // address space. Instead it clears it out so that all futre operations
  // fail.
  void DestroyAddressSpace(void *);

  // Returns a pointer to the address space associated with a memory handle.
  AddressSpace *AddressSpaceOf(void *);

  // Call into the runtime to allocate a `State` structure, and fill it with
  // the bytes from `data`.
  //
  // NOTE(pag): The purpose of this is that we want the runtime to do a memory
  //            allocation on our behalf, and we don't want to have to know
  //            how it does that allocation.
  void *AllocateStateInRuntime(const std::string &data);

  void ScheduleTask(const Task &task);
  bool TryDequeueTask(Task *task_out);
  void ResumeTask(const Task &task);

 protected:
  static Context *&GetInterceptContext(void);

 private:
  Context(const Context &&) = delete;
  Context &operator=(Context &) = delete;
  Context &operator=(Context &&) = delete;

  Context(void);

  // Create a clone of an existing `Context`.
  explicit Context(const Context &);

  // List of all address spaces.
  std::vector<AddressSpace *> address_spaces;

  std::shared_ptr<llvm::LLVMContext> context;

  std::shared_ptr<Lifter> lifter;

  std::shared_ptr<Executor> executor;

  std::list<Task> tasks;
};

using ContextPtr = std::unique_ptr<Context>;

}  // namespace vmill

#endif  // VMILL_CONTEXT_CONTEXT_H_
