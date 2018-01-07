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
#include <unistd.h>

#include "remill/Arch/Name.h"

#include "vmill/Util/AreaAllocator.h"
#include "vmill/Util/Compiler.h"

#ifndef MAP_32BIT
# define MAP_32BIT 0
#endif

#ifndef MAP_HUGETLB
# define MAP_HUGETLB 0
#endif

#ifndef MAP_HUGE_2MB
# define MAP_HUGE_2MB 0
#endif

namespace vmill {
namespace {

const uint8_t kBreakPointBytes[] = {
#if REMILL_ON_AMD64 || REMILL_ON_X86
    0xCC  // `INT3`.
#elif REMILL_ON_AARCH64
    0x00, 0x00, 0x20, 0xd4  // `BRK #0`.
#else
# error "Unsupported architecture."
#endif
};

static void FillWithBreakPoints(uint8_t *base, uint8_t *limit) {
  while (base < limit) {
    for (auto b : kBreakPointBytes) {
      *base++ = b;
    }
  }
}

}  // namespace

AreaAllocator::AreaAllocator(AreaAllocationPerms perms,
                             uintptr_t preferred_base_,
                             size_t page_size_)
    : page_size(page_size_),
      preferred_base(reinterpret_cast<void *>(preferred_base_)),
      is_executable(kAreaRWX == perms),
      base(nullptr),
      limit(nullptr),
      bump(nullptr),
      prot(PROT_READ | PROT_WRITE | (is_executable ? PROT_EXEC : 0)),
      flags(MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
            (preferred_base ? MAP_FIXED : 0)) {

  if (preferred_base_) {
    if (static_cast<uintptr_t>(static_cast<uint32_t>(preferred_base_)) ==
        preferred_base_) {
      flags |= MAP_32BIT;
    }
  }

  // TODO(pag): Try to support `MAP_HUGETLB | MAP_HUGE_2MB`.
}

AreaAllocator::~AreaAllocator(void) {
  if (base) {
    munmap(base, static_cast<size_t>(limit - base));
  }
}

void AreaAllocator::FreeAll(void) {
  bump = base;
}

uint8_t *AreaAllocator::Allocate(size_t size, size_t align) {

  // Initial allocation.
  if (unlikely(!base)) {
    uint64_t alloc_size = page_size;
    if (size > page_size) {
      alloc_size = (size + (page_size - 1UL)) & ~(page_size - 1UL);
    }

    auto ret = mmap(preferred_base, alloc_size, prot, flags, -1, 0);
    auto err = errno;
    LOG_IF(FATAL, MAP_FAILED == ret)
        << "Cannot map memory for allocator: " << strerror(err);

    LOG_IF(ERROR, preferred_base && ret != preferred_base)
        << "Cannot map memory at preferred base of " << preferred_base
        << "; got " << ret << " instead";

#ifdef MADV_HUGEPAGE
    madvise(ret, alloc_size, MADV_HUGEPAGE);
#endif

    base = reinterpret_cast<uint8_t *>(ret);
    bump = base;
    limit = base + alloc_size;

    if (is_executable) {
      FillWithBreakPoints(base, limit);
    }
  }

  // Align the bump pointer for our allocation.
  auto bump_uint = reinterpret_cast<uintptr_t>(bump);
  auto align_missing = align ? bump_uint % align : 0;
  if (align_missing) {
    bump += align - align_missing;
  }

  if ((bump + size) >= limit) {
    auto missing = (bump + size - limit);
    auto alloc_size = (missing + (page_size - 1UL)) & ~(page_size - 1UL);
    if (!alloc_size) {
      alloc_size = page_size;
    }
    auto ret = mmap(limit, alloc_size, prot, flags | MAP_FIXED, -1, 0);
    auto err = errno;
    LOG_IF(FATAL, MAP_FAILED == ret)
        << "Cannot map memory for allocator: " << strerror(err);

#ifdef MADV_HUGEPAGE
    madvise(ret, alloc_size, MADV_HUGEPAGE);
#endif

    auto ret_bytes = reinterpret_cast<uint8_t *>(ret);
    LOG_IF(FATAL, ret_bytes != limit)
        << "Cannot allocate contiguous memory for allocator.";

    if (is_executable) {
      FillWithBreakPoints(ret_bytes, ret_bytes + alloc_size);
    }

    limit += alloc_size;
  }

  auto ret = bump;
  bump += size;
  return ret;
}

}  // namespace vmill
