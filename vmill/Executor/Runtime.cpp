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
#include <cstdarg>
#include <cstdio>
#include <ostream>

#include "vmill/Arch/Arch.h"
#include "vmill/Executor/AsyncIO.h"
#include "vmill/Executor/Coroutine.h"
#include "vmill/Executor/Executor.h"
#include "vmill/Program/AddressSpace.h"
#include "vmill/Runtime/Task.h"
#include "vmill/Util/Compiler.h"

DEFINE_string(strace_output_file, "/dev/stderr",
              "If a debug build of the runtime is being used, "
              "then should be print out a trace of all the "
              "system calls?");

namespace vmill {

extern thread_local Executor *gExecutor;
thread_local Task *gTask = nullptr;

namespace {

static FILE *gStraceFile = nullptr;

// Gets a file pointer to an open file for writing the log output of strace
// info, as produced by the runtime.
static FILE *GetOpenStraceOutputFile(void) {
  if (likely(gStraceFile != nullptr)) {
    return gStraceFile;
  }

  if (FLAGS_strace_output_file.empty()) {
    return nullptr;
  }

  if (FLAGS_strace_output_file == "/dev/stderr") {
    gStraceFile = stderr;

  } else if (FLAGS_strace_output_file == "/dev/stdout") {
    gStraceFile = stdout;

  } else if (FLAGS_strace_output_file == "/dev/null") {
    FLAGS_strace_output_file.clear();
    return nullptr;

  } else {
    struct CloseStrace {
      ~CloseStrace(void) {
        if (gStraceFile) {
          fclose(gStraceFile);
        }
      }
    };
    gStraceFile = fopen(FLAGS_strace_output_file.c_str(), "w");
  }
  return gStraceFile;
}

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
      << pc_uint << " (" << memory->ToReadOnlyVirtualAddress(pc_uint) << ")"
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

__attribute__((noinline))
void vmill_break_on_fault(void) {
  asm volatile ("" : : : "memory");
}

#define MAKE_MEM_READ(ret_type, read_type, suffix, read_size, vtype) \
    __attribute__((hot)) \
    ret_type __remill_read_memory_ ## suffix( \
        AddressSpace *memory, uint64_t addr) { \
      read_type ret_val = 0; \
      if (likely(memory->TryRead(addr, &ret_val))) { \
        return ret_val; \
      } else { \
        if (likely(gTask != nullptr)) { \
          auto &fault = gTask->mem_access_fault; \
          if (kMemoryAccessNoFault == fault.kind) { \
            vmill_break_on_fault(); \
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
        vmill_break_on_fault();
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
    __attribute__((hot)) \
    AddressSpace *__remill_write_memory_ ## suffix( \
        AddressSpace *memory, uint64_t addr, input_type val) { \
      if (unlikely(!memory->TryWrite(addr, val))) { \
        if (likely(gTask != nullptr)) { \
          auto &fault = gTask->mem_access_fault; \
          if (kMemoryAccessNoFault == fault.kind) { \
            vmill_break_on_fault(); \
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
        vmill_break_on_fault();
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

// Called by the runtime to yield execution. This allows the runtime to pause
// where it is in the execution of some system call, in the hope that another
// system call will make progress.
void __vmill_yield(Task *task) {
  DCHECK(gTask != nullptr);
  DCHECK(gTask == task);
  auto coro = task->async_routine;
  DCHECK(coro != nullptr);
  coro->Pause(task);
  DCHECK(gTask == task);
}

Memory *__remill_error(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtError;
  gTask->status = kTaskStatusError;
  return memory;
}

Memory *__remill_jump(ArchState *state, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtJumpTarget;
  __vmill_yield(gTask);
  const auto lifted_func = gExecutor->FindLiftedFunctionForTask(gTask);
  return lifted_func(state, pc, memory);
}

Memory *__remill_missing_block(ArchState *state, PC pc, Memory *memory) {
  return __remill_jump(state, pc, memory);
}

Memory *__remill_function_call(ArchState *state, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtCallTarget;
  __vmill_yield(gTask);
  const auto lifted_func = gExecutor->FindLiftedFunctionForTask(gTask);
  return lifted_func(state, pc, memory);
}

Memory *__remill_function_return(ArchState *, PC pc, Memory *memory) {
  gTask->pc = pc;
  gTask->location = kTaskStoppedAtReturnTarget;
  // NOTE(pag): This does not yield, instead it just returns to its caller,
  //            thus maintaining the call-graph structure of the native code.
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

Memory *__remill_atomic_begin(Memory * memory) {
  return memory;
}

Memory *__remill_atomic_end(Memory * memory) {
  return memory;
}

Coroutine *__vmill_allocate_coroutine(void) {
  return new Coroutine;
}

void __vmill_free_coroutine(Coroutine *coro) {
  delete coro;
}

// Called by the runtime to print out information about the running system
// calls.
__attribute__((format(printf, 1, 2)))
void __vmill_strace(const char *format, ...) {
  if (auto fp = GetOpenStraceOutputFile()) {
    va_list args;
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
  }
}

// Return the current FPU exceptions, masked with `read_mask`, then clear any
// exceptions present in `clear_mask`.
int __remill_fpu_exception_test_and_clear(int read_mask, int clear_mask) {

  auto except = std::fetestexcept(read_mask);
  std::feclearexcept(clear_mask);
  return except;
}

// Implemented in assembly. This calls `__vmill_execute` (defined below) from
// inside of a coroutine.
extern void __vmill_execute_async(Task *, LiftedFunction *);

// Called by assembly in `__vmill_execute_async`.
void __vmill_execute(Task *task, LiftedFunction *lifted_func) {
  const auto memory = task->memory;
  const auto pc = task->pc;

  auto native_rounding = std::fegetround();
  std::fesetround(task->fpu_rounding_mode);
  lifted_func(task->state, pc, memory);  // Calls into lifted code.
  task->fpu_rounding_mode = std::fegetround();
  std::fesetround(native_rounding);

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
  DCHECK(gExecutor != nullptr);
  DCHECK(gTask == nullptr);

  gTask = task;

  // The task is waiting for an asynchronous operation to complete.
  DCHECK(task->async_routine != nullptr);
  if (likely(kTaskStatusResumable == task->status)) {
    task->async_routine->Resume(task);
  } else {
    DCHECK(kTaskStatusRunnable == task->status);
    const auto lifted_func = gExecutor->FindLiftedFunctionForTask(task);
    __vmill_execute_async(task, lifted_func);
  }
  gTask = nullptr;
}

}  // extern "C"
}  // namespace
}  // namespace vmill
