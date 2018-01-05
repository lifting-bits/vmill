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

#ifndef VMILL_PROGRAM_SHADOWMEMORY_H_
#define VMILL_PROGRAM_SHADOWMEMORY_H_

#include <cstdint>
#include <cstddef>
#include <new>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <type_traits>

#include "vmill/Util/AreaAllocator.h"
#include "vmill/Util/Compiler.h"

namespace vmill {

class ShadowMemory;

namespace detail {

class BoolRef {
 public:
  BoolRef(const BoolRef &) = default;
  BoolRef(BoolRef &&) = default;
  BoolRef &operator=(const BoolRef &) = default;
  BoolRef &operator=(BoolRef &&) = default;

  inline BoolRef &operator=(bool that) {
    if (that != cache) {
      if (that) {
        *byte_ptr |= test_mask;
      } else {
        *byte_ptr ^= test_mask;
      }
      cache = that;
    }
    return *this;
  }

  inline operator bool(void) const {
    return cache;
  }

 private:
  friend class ::vmill::ShadowMemory;

  BoolRef(void) = delete;

  inline BoolRef(uint8_t *byte_ptr_, uint32_t bit_offset_)
      : byte_ptr(byte_ptr_),
        test_mask(1 << bit_offset_),
        cache(0 != (*byte_ptr & test_mask)) {}

  uint8_t * const byte_ptr;
  const uint8_t test_mask;
  bool cache;
};

struct bool_tag {};
struct not_bool_tag {};

template <typename T>
struct BoolTag {
  using TagType = not_bool_tag;
  using RefType = T &;
};

template <>
struct BoolTag<bool> {
  using TagType = bool_tag;
  using RefType = BoolRef;
};

}  // namespace detail

// High-level interface for shadow memory.
class ShadowMemory {
 public:
  ~ShadowMemory(void);

  static std::unique_ptr<ShadowMemory> Get(
      uint64_t shadow_granularity_=0,
      uint64_t page_granularity_=12,
      uint64_t shadow_base_=0x100000000000);

  static void Put(std::unique_ptr<ShadowMemory> &mem);

  template <typename T, typename U>
  ALWAYS_INLINE
  static auto At(U *ptr) -> typename detail::BoolTag<T>::RefType {
    return Self()->At<T>(reinterpret_cast<uintptr_t>(ptr),
                         typename detail::BoolTag<T>::TagType());
  }

  template <typename T>
  ALWAYS_INLINE
  static auto At(uint64_t addr) -> typename detail::BoolTag<T>::RefType {
    return Self()->At<T>(addr, typename detail::BoolTag<T>::TagType());
  }

  bool AddPageForAddress(uint64_t addr);

 private:
  ShadowMemory(void) = delete;
  ShadowMemory(uint64_t shadow_granularity_,
               uint64_t page_granularity_,
               uint64_t shadow_base_);


  static ShadowMemory *Self(void);

  template <typename T>
  __attribute__((noinline, hot))
  T &At(uint64_t addr, detail::not_bool_tag) {
    if (likely(addr < shadow_base)) {
      last_shadow_address = (addr >> shadow_granularity) + shadow_base;
      last_shadow_elem_size_bits = sizeof(T) * 8;
      auto byte_ptr = reinterpret_cast<uint8_t *>(last_shadow_address);
      last_forced_shadow_byte = *byte_ptr;
      return *reinterpret_cast<T *>(byte_ptr);

    // This sucks, we need to keep out "contract" of returning referencable
    // things, but these things might actually be outside of our primary
    // shadowable range of memory. So we have to back of this code with
    // something else.
    } else {
      auto &data_ptr = reinterpret_cast<T *&>(
          out_of_range[addr >> shadow_granularity]);

      if (!data_ptr) {
        data_ptr = out_of_range_allocator.Allocate<T>();
      }

      return *data_ptr;
    }
  }

  template <typename T>
  __attribute__((noinline, hot))
  detail::BoolRef At(uint64_t addr, detail::bool_tag) {
    static_assert(std::is_same<T, bool>(), "Invalid specialization!");
    if (likely(addr < shadow_base)) {
      last_shadow_address = (addr >> shadow_granularity) + shadow_base;
      last_shadow_elem_size_bits = 1;
      auto byte_ptr = reinterpret_cast<uint8_t *>(last_shadow_address);
      last_forced_shadow_byte = *byte_ptr;
      detail::BoolRef ref(byte_ptr, last_shadow_address % 8);
      return ref;

    } else {
      auto &data_ptr = reinterpret_cast<uint8_t *&>(
          out_of_range[addr >> shadow_granularity]);
      if (!data_ptr) {
        data_ptr = out_of_range_allocator.Allocate(1, 0);
        *data_ptr = 0;
      }
      detail::BoolRef ref(data_ptr, 0);
      return ref;
    }
  }

  const uint64_t shadow_granularity;
  const uint64_t shadow_base;
  const uint64_t page_granularity;

  uint64_t last_shadow_address;
  uint32_t last_shadow_elem_size_bits;
  uint8_t last_forced_shadow_byte;

  // Tracks mapped pages in the shadowable range,
  std::vector<void *> shadow_pages;
  size_t last_shadow_page_size;

  // Used to store shadow information about bytes that are out of the
  // shadowable range.
  std::unordered_map<uint64_t, void *> out_of_range;

  // Allocator of objects for out of range objects.
  AreaAllocator out_of_range_allocator;
};

}  // namespace vmill

#endif  // VMILL_PROGRAM_SHADOWMEMORY_H_
