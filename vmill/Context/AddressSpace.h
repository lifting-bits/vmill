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

#ifndef VMILL_CONTEXT_ADDRESSSPACE_H_
#define VMILL_CONTEXT_ADDRESSSPACE_H_

#include <cstdint>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct Memory;

namespace vmill {

class AddressSpace;
using AddressSpacePtr = std::unique_ptr<AddressSpace>;
using AddressSpaceMap = std::unordered_map<Memory *, AddressSpacePtr>;
using AddressSpaceVec = std::vector<AddressSpacePtr>;

// Forward declaration of underlying memory map type.
class MemoryMap;
using MemoryMapPtr = std::shared_ptr<MemoryMap>;

// Basic memory implementation.
class AddressSpace {
 public:
  AddressSpace(void);

  // Creates a copy/clone of another address space.
  explicit AddressSpace(const AddressSpace &);
  explicit AddressSpace(const AddressSpacePtr &);

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

  // Read/write a byte to memory. Returns `false` if the read or write failed.
  bool TryRead(uint64_t addr, uint8_t *val);
  bool TryWrite(uint64_t addr, uint8_t val);

  // Read a byte as an executable byte. This is used for instruction decoding.
  // Returns `false` if the read failed. This function operates on the state
  // of a page, and may result in broad-reaching cache invalidations.
  bool TryReadExecutable(uint64_t addr, uint8_t *val);

  // Change the permissions of some range of memory. This can split memory
  // maps.
  void SetPermissions(uint64_t base, size_t size, bool can_read,
                      bool can_write, bool can_exec);

  // Adds a new memory mapping with default read/write permissions.
  void AddMap(uint64_t base, size_t size,
              bool can_read=true, bool can_write=true, bool can_exec=false);

  // Removes a memory mapping.
  void RemoveMap(uint64_t base, size_t size);

  // Log out the current state of the memory maps.
  void LogMaps(void);

  // Find the smallest mapped memory range limit address that is greater
  // than `find`.
  bool NearestLimitAddress(uint64_t find, uint64_t *next_end) const;

  // Find the largest mapped memory range base address that is less-than
  // or equal to `find`.
  bool NearestBaseAddress(uint64_t find, uint64_t *next_end) const;

  // Have we observed a write to executable memory since our last attempt
  // to read from executable memory?
  bool CodeVersionIsInvalid(void) const;

  // Returns a hash of all executable code. Useful for getting the current
  // version of the code.
  //
  // NOTE(pag): If the code version is invalid, then this will recompute it,
  //            thereby making it valid.
  uint64_t CodeVersion(void);

 private:
  AddressSpace(AddressSpace &&) = delete;
  AddressSpace &operator=(const AddressSpace &) = delete;
  AddressSpace &operator=(const AddressSpace &&) = delete;

  // Check that the ranges are sane.
  void CheckRanges(std::vector<MemoryMapPtr> &);

  // Recreate the `range_base_to_index` and `range_limit_to_index` indices.
  void CreatePageToRangeMap(void);

  // Find the memory map containing `addr`. If none is found then a "null"
  // map pointer is returned, whose operations will all fail.
  //
  // Note:  This may return a reference into `page_to_map`, and so be careful
  //        when using it!
  const MemoryMapPtr &FindRange(uint64_t addr);

  // Used to represent an invalid memory map.
  MemoryMapPtr invalid_map;

  // Sorted list of mapped memory page ranges.
  std::vector<MemoryMapPtr> maps;

  // A cache mapping pages accessed to the range.
  std::unordered_map<uint64_t, MemoryMapPtr> page_to_map;

  // Sets of pages that are readable, writable, and executable.
  std::unordered_set<uint64_t> page_is_readable;
  std::unordered_set<uint64_t> page_is_writable;
  std::unordered_set<uint64_t> page_is_executable;

  // Is the address space dead? This means that all operations on it
  // will be muted.
  bool is_dead;

  // Has there been a write to executable memory since the previous read from
  // executable memory?
  bool code_version_is_invalid;

  // An identifier that links together this address space, and any ones that
  // are cloned from it, so that we can partition code caches according to
  // a common ancestry.
  uint64_t code_version;
};

}  // namespace vmill

#endif  // VMILL_CONTEXT_ADDRESSSPACE_H_
