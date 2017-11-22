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

#ifndef VMILL_UTIL_AREAALLOCATOR_H_
#define VMILL_UTIL_AREAALLOCATOR_H_

#include <cstdint>

namespace vmill {

enum AreaAllocationPerms {
  kAreaRW,
  kAreaRWX
};

enum AreaPreferences : uint64_t {
  kAreaCodeCacheCode = 0x100000000000ULL,
  kAreaCodeCacheData = 0x200000000000ULL,
  kAreaCodeCacheIndex = 0x300000000000ULL,
  kAreaAddressSpace = 0x400000000000ULL
};

// Bump-pointer allocator for a contiguous region of memory.
class AreaAllocator {
 public:
  AreaAllocator(AreaAllocationPerms perms, uintptr_t preferred_base_=0);
  ~AreaAllocator(void);

  uint8_t *Allocate(size_t size, size_t align=0);

  template <typename T>
  inline bool Contains(T *addr_) const {
    auto addr = reinterpret_cast<uint8_t *>(addr_);
    return base <= addr && addr < bump;
  }

 private:
  AreaAllocator(void) = delete;
  AreaAllocator(const AreaAllocator &) = delete;

  void *preferred_base;
  bool executable;
  uint8_t *base;
  uint8_t *limit;
  uint8_t *bump;
};

}  // namespace vmill

#endif  // VMILL_UTIL_AREAALLOCATOR_H_
