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

#ifndef VMILL_RUNTIME_INTRINSICS_H_
#define VMILL_RUNTIME_INTRINSICS_H_

#include "remill/Arch/Runtime/Intrinsics.h"

#include "vmill/Runtime/Task.h"

extern "C" {

// Set the location of a task.
[[gnu::used]]
extern void __vmill_set_location(addr_t pc, vmill::TaskStopLocation loc);

[[gnu::used, gnu::const]]
extern Memory *__vmill_allocate_address_space(void);

[[gnu::used]]
extern void __vmill_free_address_space(Memory *);

// Clone an address space. The clone will be a copy-on-write version of the
// original. It is safe to use the original and clone concurrently. This is
// useful for implementing things like multiprocessing.
[[gnu::used, gnu::const]]
extern Memory *__vmill_clone_address_space(Memory *);

// Returns true if the memory at address `addr` is readable.
[[gnu::used, gnu::const]]
extern bool __vmill_can_read_byte(Memory *memory, addr_t addr);

// Returns true if the memory at address `addr` is writable.
[[gnu::used, gnu::const]]
extern bool __vmill_can_write_byte(Memory *memory, addr_t addr);

// Requests a new memory allocation from the VMM. The caller is responsible
// for specifying where the memory should be allocated. This means that the
// caller is in charge of emulating the `mmap` behavior of a program, e.g.
// to emulate things like ASLR. This also means that passing in `0` is a valid
// thing and that it can/will be allocated.
extern Memory *__vmill_allocate_memory(Memory *memory, addr_t where,
                                       addr_t size, const char *name,
                                       uint64_t offset);

// Tells the VMM to free some memory.
extern Memory *__vmill_free_memory(Memory *memory, addr_t where, addr_t size);

// Tells the VMM to change the permissions of some memory range.
extern Memory *__vmill_protect_memory(Memory *memory, addr_t where,
                                      addr_t size, bool can_read,
                                      bool can_write, bool can_exec);

// Returns `true` iff a given page is mapped (independent of permissions).
extern bool __vmill_is_mapped_address(Memory *memory, addr_t where);

// Finds some unmapped memory.
addr_t __vmill_find_unmapped_address(Memory *memory, addr_t base,
                                     addr_t limit, addr_t size);

}  // extern C

size_t NumReadableBytes(Memory *memory, addr_t addr, size_t size);
size_t NumWritableBytes(Memory *memory, addr_t addr, size_t size);

inline static bool CanReadMemory(Memory *memory, addr_t addr, size_t size) {
  return size == NumReadableBytes(memory, addr, size);
}

inline static bool CanWriteMemory(Memory *memory, addr_t addr, size_t size) {
  return size == NumWritableBytes(memory, addr, size);
}

Memory *CopyToMemory(Memory *memory, addr_t addr,
                     const void *data, size_t size);

void CopyFromMemory(Memory *memory, void *data, addr_t addr, size_t size);

template <typename T>
inline static T ReadMemory(Memory *memory, addr_t addr) {
  T val{};
  CopyFromMemory(memory, &val, addr, sizeof(T));
  return val;
}

template <typename T>
inline static bool TryReadMemory(Memory *memory, addr_t addr, T *val) {
  if (CanReadMemory(memory, addr, sizeof(T))) {
    CopyFromMemory(memory, val, addr, sizeof(T));
    return true;
  } else {
    return false;
  }
}

// You don't want to be using this function, it doesn't make sense to copy a
// pointer into an emulated address space.
template <typename T>
inline static bool TryWriteMemory(Memory *&, addr_t, const T *) {
  abort();
}

template <typename T>
inline static bool TryWriteMemory(Memory *&memory, addr_t addr, const T &val) {
  if (CanWriteMemory(memory, addr, sizeof(T))) {
    memory = CopyToMemory(memory, addr, &val, sizeof(T));
    return true;
  } else {
    return false;
  }
}

size_t CopyStringFromMemory(Memory *memory, addr_t addr,
                            char *val, size_t max_len);

size_t CopyStringToMemory(Memory *memory, addr_t addr, const char *val,
                          size_t len);

inline static addr_t AlignToPage(addr_t addr) {
  return addr & ~4095UL;
}

inline static addr_t AlignToNextPage(addr_t addr) {
  return (addr + 4095UL) & ~4095UL;
}

#endif  // VMILL_RUNTIME_INTRINSICS_H_
