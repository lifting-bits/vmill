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

#include <glog/logging.h>

#include <cerrno>
#include <sys/mman.h>

#include "vmill/Util/AreaAllocator.h"
#include "vmill/Util/Compiler.h"

#ifndef MAP_HUGETLB
# define MAP_HUGETLB 0
#endif

#ifndef MAP_HUGE_2MB
# define MAP_HUGE_2MB 0
#endif

namespace vmill {
namespace {

enum : size_t {
  k2MiB = 2097152ULL
};

}  // namespace

AreaAllocator::AreaAllocator(AreaAllocationPerms perms,
                             uintptr_t preferred_base_)
    : preferred_base(reinterpret_cast<void *>(preferred_base_)),
      executable(kAreaRWX == perms),
      base(nullptr),
      limit(nullptr),
      bump(nullptr) {}

AreaAllocator::~AreaAllocator(void) {
  if (base) {
    munmap(base, static_cast<size_t>(limit - base));
  }
}

uint8_t *AreaAllocator::Allocate(size_t size, size_t align) {
  const int prot = PROT_READ | PROT_WRITE | (executable ? PROT_EXEC : 0);
  const int flags = MAP_PRIVATE | MAP_ANONYMOUS |
                    (preferred_base ? MAP_FIXED : 0)
                    /* | MAP_HUGETLB | MAP_HUGE_2MB */;

  // Initial allocation.
  if (unlikely(!base)) {
    uint64_t alloc_size = k2MiB;
    if (size > k2MiB) {
      alloc_size = (size + (k2MiB - 1)) & ~(k2MiB - 1);
    }

    auto ret = mmap(preferred_base, alloc_size, prot, flags, -1, 0);
    auto err = errno;
    LOG_IF(FATAL, MAP_FAILED == ret)
        << "Cannot map memory for allocator: " << strerror(err);

    LOG_IF(ERROR, preferred_base && ret != preferred_base)
        << "Cannot map memory at preferred base of " << preferred_base
        << "; got " << ret << " instead";

    base = reinterpret_cast<uint8_t *>(ret);
    bump = base;
    limit = base + k2MiB;
  }

  // Align the bump pointer for our allocation.
  auto bump_uint = reinterpret_cast<uintptr_t>(bump);
  auto align_missing = align ? bump_uint % align : 0;
  if (align_missing) {
    bump += align - align_missing;
  }

  if ((bump + size) >= limit) {
    auto missing = (bump + size - limit);
    auto alloc_size = (missing + (k2MiB - 1)) & ~(k2MiB - 1);
    if (!alloc_size) {
      alloc_size = k2MiB;
    }
    auto ret = mmap(limit, alloc_size, prot, flags | MAP_FIXED, -1, 0);
    auto err = errno;
    LOG_IF(FATAL, MAP_FAILED == ret)
        << "Cannot map memory for allocator: " << strerror(err);

    LOG_IF(FATAL, ret != limit)
        << "Cannot allocate contiguous memory for allocator.";

    limit += alloc_size;
  }

  auto ret = bump;
  bump += size;
  return ret;
}

}  // namespace vmill
