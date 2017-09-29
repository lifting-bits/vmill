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

#include <algorithm>

#include "vmill/Runtime/Generic/Intrinsics.h"

size_t NumReadableBytes(Memory *memory, addr_t addr, size_t size) {
  addr_t i = 0;
  for (; i < size; i += 4096) {
    if (!__vmill_can_read_byte(memory, addr + static_cast<addr_t>(i))) {
      return i ? ((addr + i) & ~4095UL) - addr : 0;
    }
  }
  return std::min<size_t>(i, size);
}

size_t NumWritableBytes(Memory *memory, addr_t addr, size_t size) {
  addr_t i = 0;
  for (; i < size; i += 4096) {
    if (!__vmill_can_write_byte(memory, addr + static_cast<addr_t>(i))) {
      return i ? ((addr + i) & ~4095UL) - addr : 0;
    }
  }
  return std::min<size_t>(i, size);
}

Memory *CopyToMemory(Memory *memory, addr_t addr,
                     const void *data, size_t size) {
  auto data_bytes = reinterpret_cast<const uint8_t *>(data);
  for (size_t i = 0; i < size; ++i) {
    memory = __remill_write_memory_8(
        memory, addr + static_cast<addr_t>(i), data_bytes[i]);
  }
  return memory;
}

void CopyFromMemory(Memory *memory, void *data, addr_t addr, size_t size) {
  auto data_bytes = reinterpret_cast<uint8_t *>(data);
  for (size_t i = 0; i < size; ++i) {
    data_bytes[i] = __remill_read_memory_8(
        memory, addr + static_cast<addr_t>(i));
  }
}

size_t CopyStringFromMemory(Memory *memory, addr_t addr,
                            char *val, size_t max_len) {
  size_t i = 0;
  max_len = NumReadableBytes(memory, addr, max_len);
  for (; i < max_len; ++i) {
    val[i] = static_cast<char>(__remill_read_memory_8(memory, addr));
    if (!val[i]) {
      break;
    }
  }
  return i;
}

size_t CopyStringToMemory(Memory *memory, addr_t addr, const char *val,
                          size_t len) {
  size_t i = 0;
  len = NumWritableBytes(memory, addr, len);
  for (; i < len; ++i) {
    memory = __remill_write_memory_8(
        memory, addr, static_cast<uint8_t>(val[i]));
    if (!val[i]) {
      break;
    }
  }
  return i;
}

// Memory barriers types, see: http://g.oswego.edu/dl/jmm/cookbook.html
Memory *__remill_barrier_load_load(Memory * memory) {
  return memory;
}

Memory *__remill_barrier_load_store(Memory * memory) {
  return memory;
}

Memory *__remill_barrier_store_load(Memory * memory) {
  return memory;
}

Memory *__remill_barrier_store_store(Memory * memory) {
  return memory;
}

// Atomic operations. The address/size are hints, but the granularity of the
// access can be bigger. These have implicit StoreLoad semantics.
Memory *__remill_atomic_begin(Memory * memory) {
  return memory;
}

Memory *__remill_atomic_end(Memory * memory) {
  return memory;
}
