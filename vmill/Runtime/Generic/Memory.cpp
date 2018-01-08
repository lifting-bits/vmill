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

#include "remill/Arch/Runtime/Operators.h"

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
    val[i] = static_cast<char>(__remill_read_memory_8(
        memory, addr + static_cast<addr_t>(i)));
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
        memory, addr + static_cast<addr_t>(i), static_cast<uint8_t>(val[i]));
    if (!val[i]) {
      break;
    }
  }
  return i;
}

#define MAKE_CMPXCHG(size, ...) \
    Memory *__remill_compare_exchange_memory_ ## size( \
        Memory *memory, addr_t addr, \
        uint ## size ## _t &expected, \
        uint ## size ## _t __VA_ARGS__ desired) { \
      auto old_val = __remill_read_memory_ ## size(memory, addr); \
      if (old_val == expected) { \
        memory = __remill_write_memory_ ## size(memory, addr, desired); \
      } else { \
        expected = old_val; \
        memory = __remill_write_memory_ ## size(memory, addr, old_val); \
      } \
      return memory; \
    }

extern "C" {
MAKE_CMPXCHG(8)
MAKE_CMPXCHG(16)
MAKE_CMPXCHG(32)
MAKE_CMPXCHG(64)
MAKE_CMPXCHG(128, &)
}  // extern C
#undef MAKE_CMPXCHG

#define MAKE_RMW(name, size, op) \
    Memory *__remill_fetch_and_ ## name ## _ ## size( \
        Memory *memory, addr_t addr, uint ## size ## _t &value) { \
      auto old_val = __remill_read_memory_ ## size(memory, addr); \
      uint ## size ## _t new_val = old_val op value; \
      value = old_val; \
      return __remill_write_memory_ ## size(memory, addr, new_val); \
    }

extern "C" {

MAKE_RMW(add, 8, +)
MAKE_RMW(add, 16, +)
MAKE_RMW(add, 32, +)
MAKE_RMW(add, 64, +)

MAKE_RMW(sub, 8, -)
MAKE_RMW(sub, 16, -)
MAKE_RMW(sub, 32, -)
MAKE_RMW(sub, 64, -)

MAKE_RMW(or, 8, |)
MAKE_RMW(or, 16, |)
MAKE_RMW(or, 32, |)
MAKE_RMW(or, 64, |)

MAKE_RMW(and, 8, &)
MAKE_RMW(and, 16, &)
MAKE_RMW(and, 32, &)
MAKE_RMW(and, 64, &)

MAKE_RMW(xor, 8, ^)
MAKE_RMW(xor, 16, ^)
MAKE_RMW(xor, 32, ^)
MAKE_RMW(xor, 64, ^)

}  // extern C
#undef MAKE_RMW
