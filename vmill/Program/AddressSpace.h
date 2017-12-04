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

#ifndef VMILL_MEMORY_ADDRESSSPACE_H_
#define VMILL_MEMORY_ADDRESSSPACE_H_

#include <cstdint>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "vmill/Program/MappedRange.h"

struct Memory {};

namespace vmill {

enum class CodeVersion : uint64_t;
enum class PC : uint64_t;

// Basic memory implementation.
class AddressSpace : public Memory {
 public:
  AddressSpace(void);

  // Creates a copy/clone of another address space.
  explicit AddressSpace(const AddressSpace &);

  // Kill this address space. This prevents future allocations, and removes
  // all existing ranges.
  void Kill(void);

  // Returns `true` if this address space is "dead".
  bool IsDead(void) const;

  // Returns `true` if the byte at address `addr` is readable,
  // writable, or executable, respectively.
  bool CanRead(uint64_t addr) const;
  bool CanWrite(uint64_t addr) const;
  bool CanExecute(uint64_t addr) const;

  // Get the code version associated with some program counter.
  CodeVersion ComputeCodeVersion(PC pc);

  __attribute__((hot))
  bool TryRead(uint64_t addr, void *val, size_t size);

  __attribute__((hot))
  bool TryWrite(uint64_t addr, const void *val, size_t size);

  // Read/write a byte to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, uint8_t *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, uint8_t val);

  // Read/write a word to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, uint16_t *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, uint16_t val);

  // Read/write a dword to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, uint32_t *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, uint32_t val);

  // Read/write a qword to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, uint64_t *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, uint64_t val);

  // Read/write a float to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, float *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, float val);

  // Read/write a double to memory. Returns `false` if the read or write failed.
  __attribute__((hot)) bool TryRead(uint64_t addr, double *val);
  __attribute__((hot)) bool TryWrite(uint64_t addr, double val);

  // Return the virtual address of the memory backing `addr`.
  __attribute__((hot)) void *ToReadWriteVirtualAddress(uint64_t addr);

  // Return the virtual address of the memory backing `addr`.
  __attribute__((hot)) const void *ToReadOnlyVirtualAddress(uint64_t addr);

  // Read a byte as an executable byte. This is used for instruction decoding.
  // Returns `false` if the read failed. This function operates on the state
  // of a page, and may result in broad-reaching cache invalidations.
  __attribute__((hot)) bool TryReadExecutable(PC addr, uint8_t *val);

  // Change the permissions of some range of memory. This can split memory
  // maps.
  void SetPermissions(uint64_t base, size_t size, bool can_read,
                      bool can_write, bool can_exec);

  // Adds a new memory mapping with default read/write permissions.
  void AddMap(uint64_t base, size_t size, const char *name=nullptr,
              uint64_t offset=0);

  // Removes a memory mapping.
  void RemoveMap(uint64_t base, size_t size);

  // Log out the current state of the memory maps.
  void LogMaps(std::ostream &stream) const;

  // Returns `true` if `find` is a mapped address (with any permission).
  bool IsMapped(uint64_t find) const;

  // Find a hole big enough to hold `size` bytes in the address space,
  // such that the hole falls within the bounds `[min, max)`.
  bool FindHole(uint64_t min, uint64_t max, uint64_t size,
                uint64_t *hole) const;

  // Mark some PC in this address space as being a known trace head. This is
  // used for helping the decoder to not repeat past work.
  void MarkAsTraceHead(PC pc);

  // Check to see if a given program counter is a trace head.
  bool IsMarkedTraceHead(PC pc) const;

 private:
  AddressSpace(AddressSpace &&) = delete;
  AddressSpace &operator=(const AddressSpace &) = delete;
  AddressSpace &operator=(const AddressSpace &&) = delete;

  // Recreate the `range_base_to_index` and `range_limit_to_index` indices.
  void CreatePageToRangeMap(void);

  // Permission checking on page-aligned `addr` values.
  bool CanReadAligned(uint64_t addr) const;
  bool CanWriteAligned(uint64_t addr) const;
  bool CanExecuteAligned(uint64_t addr) const;

  // Find the memory map containing `addr`. If none is found then a "null"
  // map pointer is returned, whose operations will all fail.
  __attribute__((hot)) const MemoryMapPtr &FindRange(uint64_t addr);
  __attribute__((hot)) const MemoryMapPtr &FindWNXRange(uint64_t addr);

  // Find the range associated with a page-aligned value of `addr`.
  __attribute__((hot)) const MemoryMapPtr &FindRangeAligned(uint64_t addr);
  __attribute__((hot)) const MemoryMapPtr &FindWNXRangeAligned(uint64_t addr);

  // Used to represent an invalid memory map.
  MemoryMapPtr invalid_min_map;
  MemoryMapPtr invalid_max_map;

  // Sorted list of mapped memory page ranges.
  std::vector<MemoryMapPtr> maps;

  // A cache mapping pages accessed to the range.
  using PageCache = std::unordered_map<uint64_t, MemoryMapPtr>;
  PageCache page_to_map;
  PageCache wnx_page_to_map;

  PageCache::iterator last_map;
  PageCache::iterator last_wnx_map;

  // Sets of pages that are readable, writable, and executable.
  std::unordered_set<uint64_t> page_is_readable;
  std::unordered_set<uint64_t> page_is_writable;
  std::unordered_set<uint64_t> page_is_executable;

  // Is the address space dead? This means that all operations on it
  // will be muted.
  bool is_dead;

  // Set of lifted trace heads observed for this code version.
  std::unordered_set<uint64_t> trace_heads;
};

}  // namespace vmill

#endif  // VMILL_MEMORY_ADDRESSSPACE_H_
