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
#include <type_traits>

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

  static ShadowMemory *Get(uint64_t shadow_granularity_=0,
                           uint64_t page_granularity_=12,
                           uint64_t shadow_base_=0x100000000000);

  template <typename T, typename U>
  ALWAYS_INLINE
  static auto At(U *ptr) -> typename detail::BoolTag<T>::RefType {
    return Self()->At(reinterpret_cast<uintptr_t>(ptr),
                      typename detail::BoolTag<T>::TagType());
  }

  template <typename T, typename U>
  ALWAYS_INLINE
  static auto At(uint64_t addr) -> typename detail::BoolTag<T>::RefType {
    return Self()->At(addr, typename detail::BoolTag<T>::TagType());
  }

  bool AddPageForAddress(uint64_t addr);

 private:
  ShadowMemory(void) = delete;
  ShadowMemory(uint64_t shadow_granularity_,
               uint64_t page_granularity_,
               uint64_t shadow_base_);


  static ShadowMemory *Self(void);

  template <typename T>
  inline T &At(uint64_t addr, detail::not_bool_tag) {
    last_page_address = (addr >> page_granularity) + shadow_base;
    last_shadow_address = (addr >> shadow_granularity) + shadow_base;
    last_shadow_elem_size_bits = sizeof(T) * 8;
    auto byte_ptr = reinterpret_cast<uint8_t *>(last_shadow_address);
    last_forced_shadow_byte = *byte_ptr;
    return *reinterpret_cast<T *>(byte_ptr);
  }

  inline detail::BoolRef At(uint64_t addr, detail::bool_tag) {
    last_page_address = (addr >> page_granularity) + shadow_base;
    last_shadow_address = (addr >> shadow_granularity) + shadow_base;
    last_shadow_elem_size_bits = 1;
    auto byte_ptr = reinterpret_cast<uint8_t *>(last_shadow_address);
    last_forced_shadow_byte = *byte_ptr;
    detail::BoolRef ref(byte_ptr, last_shadow_address % 8);
    return ref;
  }

  const uint64_t shadow_granularity;
  const uint64_t shadow_base;
  const uint64_t page_granularity;

  uint64_t last_page_address;
  uint64_t last_shadow_address;
  uint32_t last_shadow_elem_size_bits;
  uint8_t last_forced_shadow_byte;

  struct ShadowPage {
    inline ShadowPage(void *base_, size_t size_)
        : base(base_),
          size(size_) {}

    ~ShadowPage(void);

    void *base;
    size_t size;
  };

  using ShadowPagePtr = std::unique_ptr<ShadowPage>;

  std::unordered_map<uint64_t, ShadowPagePtr> shadow_page_map;
};

}  // namespace vmill

#endif  // VMILL_PROGRAM_SHADOWMEMORY_H_
