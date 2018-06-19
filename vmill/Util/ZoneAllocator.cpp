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

#include "vmill/Util/ZoneAllocator.h"

namespace vmill {
namespace {

enum : size_t {
  kPageSize = 4096ULL
};

}  // namespace

ZoneAllocator::ZoneAllocator(AreaAllocationPerms perms,
                             uintptr_t preferred_base,
                             size_t page_size)
    : allocator(perms, preferred_base, page_size) {}

ZoneAllocation ZoneAllocator::Allocate(size_t size) {
  ZoneAllocation alloc = {};
  auto lb = free_list.lower_bound(size);
  if (lb != free_list.end() && !lb->second.empty()) {
    alloc.base = lb->second.back();
    alloc.size = lb->first;
    lb->second.pop_back();

    if (alloc.size != size) {
      CHECK(alloc.size >= size);

      auto diff = alloc.size - size;
      if (diff > kPageSize) {
        DLOG(INFO)
            << "Splitting previously freed 0x" << std::hex << alloc.size
            << "-byte allocation for a 0x" << size << "-byte allocation"
            << std::dec;

        ZoneAllocation split = {alloc.base, diff};
        Free(split);

        alloc.base = &(alloc.base[diff]);
        alloc.size = size;
      } else {
        DLOG(INFO)
            << "Re-using a previously freed 0x" << std::hex << alloc.size
            << "-byte allocation for a 0x" << size << "-byte allocation"
            << std::dec;
      }
    }

  } else {
    alloc.base = allocator.Allocate(size, 64  /* Cache line size */);
    alloc.size = size;
  }
  bzero(alloc.base, size);
  return alloc;
}

void ZoneAllocator::Free(ZoneAllocation &alloc) {
  if (alloc.base) {
    free_list[alloc.size].push_back(alloc.base);
    alloc.Reset();
  }
}

}  // namespace vmill
