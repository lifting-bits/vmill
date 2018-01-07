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
#include <new>

namespace vmill {

enum AreaAllocationPerms {
  kAreaRW,
  kAreaRWX
};

enum AreaPreferences : uint64_t {
  kAreaCodeCacheCode    = 0x80000000ULL,  // 2 GiB.
  kAreaCodeCacheData    = 0xC0000000ULL,  // 3 GiB.
  kAreaCodeCacheIndex   = 0x10000000000ULL,
  kAreaAddressSpace     = 0x20000000000ULL,
  kAreaCoroutineStacks  = 0x30000000000ULL,
  kAreaRuntimeHeap      = 0x40000000000ULL,
};

enum : size_t {
  k2MiB = 2097152ULL
};

// Bump-pointer allocator for a contiguous region of memory.
class AreaAllocator {
 public:
  AreaAllocator(AreaAllocationPerms perms, uintptr_t preferred_base_=0,
                size_t page_size_=k2MiB);
  ~AreaAllocator(void);

  template <typename T, typename... Args>
  inline T *Allocate(Args&&... args) {
    return new (Allocate(sizeof(T), alignof(T))) T(std::forward<Args>(args)...);
  }

  uint8_t *Allocate(size_t size, size_t align=0);

  template <typename T>
  inline bool Contains(T *addr_) const {
    auto addr = reinterpret_cast<uint8_t *>(addr_);
    return base <= addr && addr < bump;
  }

  void FreeAll(void);

 private:
  AreaAllocator(void) = delete;
  AreaAllocator(const AreaAllocator &) = delete;

  size_t page_size;
  void *preferred_base;
  bool is_executable;
  uint8_t *base;
  uint8_t *limit;
  uint8_t *bump;
  int prot;
  int flags;
};

}  // namespace vmill

#endif  // VMILL_UTIL_AREAALLOCATOR_H_
