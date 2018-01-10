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

#include "vmill/Executor/Memory.h"
#include "vmill/Util/ZoneAllocator.h"

#include "third_party/liballoc/liballoc.h"

#ifdef __APPLE__
# define TO_STR_(x) #x
# define TO_STR(x) TO_STR_(x)
# define SYM(a) TO_STR(_ ## a)
#else
# define SYM(a) #a
#endif

namespace vmill {
namespace {

static ZoneAllocator gRuntimeHeap(kAreaRW, kAreaRuntimeHeap, 4096);

extern "C" {

int liballoc_lock() {
  return 0;
}

int liballoc_unlock() {
  return 0;
}

void *liballoc_alloc(int num_pages) {
  auto alloc = gRuntimeHeap.Allocate(static_cast<size_t>(num_pages * 4096));
  return alloc.base;
}

int liballoc_free(void *base, int num_pages) {
  ZoneAllocation alloc = {};
  alloc.base = reinterpret_cast<uint8_t *>(base);
  alloc.size = static_cast<size_t>(num_pages * 4096);
  gRuntimeHeap.Free(alloc);
  return 0;
}

}  // extern C
}  // namespace

MemoryManagerTool::MemoryManagerTool(std::unique_ptr<Tool> tool_)
    : ProxyTool(std::move(tool_)) {

  liballoc_initialize();

  alloc_funcs[SYM(malloc)] = reinterpret_cast<uintptr_t>(runtime_malloc);
  alloc_funcs[SYM(free)] = reinterpret_cast<uintptr_t>(runtime_free);
  alloc_funcs[SYM(realloc)] = reinterpret_cast<uintptr_t>(runtime_realloc);
  alloc_funcs[SYM(calloc)] = reinterpret_cast<uintptr_t>(runtime_calloc);
  alloc_funcs[SYM(_Znam)] = reinterpret_cast<uintptr_t>(runtime_malloc);
  alloc_funcs[SYM(_Znwm)] = reinterpret_cast<uintptr_t>(runtime_malloc);
  alloc_funcs[SYM(_ZdlPv)] = reinterpret_cast<uintptr_t>(runtime_free);
  alloc_funcs[SYM(_ZdaPv)] = reinterpret_cast<uintptr_t>(runtime_free);

  // TODO(pag): There are other variants of `operator new`
  //            and `operator delete`.

  // TODO(pag): There are other libc and libc++ functions that allocate
  //            memory in the heap.
}

// Called when lifted bitcode or the runtime needs to resolve an external
// symbol, in our case, symbols of functions that can invoke dynamic memory
// allocations.
uint64_t MemoryManagerTool::FindSymbolForLinking(
    const std::string &name, uint64_t resolved) {
  auto it = alloc_funcs.find(name);
  if (it != alloc_funcs.end()) {
    resolved = it->second;
  }
  return ProxyTool::FindSymbolForLinking(name, resolved);
}

}  // namespace vmill
