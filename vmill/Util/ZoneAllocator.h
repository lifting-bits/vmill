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

#ifndef VMILL_UTIL_ZONEALLOCATOR_H_
#define VMILL_UTIL_ZONEALLOCATOR_H_

#include <map>
#include <vector>

#include "vmill/Util/AreaAllocator.h"

namespace vmill {

struct ZoneAllocation {
  uint8_t *base;
  size_t size;

  inline void Reset(void) {
    base = nullptr;
    size = 0;
  }
};

class ZoneAllocator {
 public:
  ZoneAllocator(AreaAllocationPerms perms,
                uintptr_t preferred_base=0,
                size_t page_size=k2MiB);

  ZoneAllocation Allocate(size_t size);

  void Free(ZoneAllocation &alloc);

 private:
  AreaAllocator allocator;
  std::map<size_t, std::vector<uint8_t *>> free_list;
};


}  // namespace vmill

#endif  // VMILL_UTIL_ZONEALLOCATOR_H_
