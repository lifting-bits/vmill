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

#ifndef VMILL_MEMORY_MAPPEDRANGE_H_
#define VMILL_MEMORY_MAPPEDRANGE_H_

#include <cstdint>
#include <memory>

#include "vmill/Util/Compiler.h"

namespace vmill {

enum class CodeVersion : uint64_t;

// Forward declaration of underlying memory map type.
class MappedRange;
using MemoryMapPtr = std::shared_ptr<MappedRange>;

// Basic information about some region of mapped memory within an address space.
class MappedRange {
 public:
  static MemoryMapPtr Create(uint64_t base_address_, uint64_t limit_address_,
                             const char *name_, uint64_t offset_);
  static MemoryMapPtr CreateInvalid(uint64_t base_address_,
                                    uint64_t limit_address_);

  virtual ~MappedRange(void);

  virtual bool IsValid(void) const = 0;

  ALWAYS_INLINE uint64_t BaseAddress(void) const {
    return base_address;
  }

  ALWAYS_INLINE uint64_t LimitAddress(void) const {
    return limit_address;
  }

  ALWAYS_INLINE const char *Name(void) const {
    return name;
  }

  ALWAYS_INLINE uint64_t Offset(void) const {
    return offset;
  }

  ALWAYS_INLINE uint64_t Size(void) const {
    return limit_address - base_address;
  }

  ALWAYS_INLINE bool Contains(uint64_t address) const {
    return base_address <= address && address < limit_address;
  }

  ALWAYS_INLINE bool LessThan(const MemoryMapPtr &left,
                              const MemoryMapPtr &right) {
    return left->BaseAddress() < right->BaseAddress();
  }

  // Invalidate the current "code version" of this range.
  virtual void InvalidateCodeVersion(void) = 0;

  // Compute the "code version" of this range. This is only relevant for
  // ranges with executable permissions.
  virtual CodeVersion ComputeCodeVersion(void) = 0;

  // Read a byte of memory from this range.
  virtual bool Read(uint64_t address, uint8_t *out_val) = 0;

  // Write a byte of memory into this range.
  virtual bool Write(uint64_t address, uint8_t val) = 0;

  // Create a clone of this range.
  virtual MemoryMapPtr Clone(void) = 0;

  // Create a copy of a portion of this range.
  virtual MemoryMapPtr Copy(uint64_t clone_base, uint64_t clone_limit) = 0;

  // Return the virtual address of the memory backing `addr`.
  virtual void *ToReadWriteVirtualAddress(uint64_t addr);

  // Return the virtual address of the memory backing `addr`.
  virtual const void *ToReadOnlyVirtualAddress(uint64_t addr);

  // Type of this mapped range.
  virtual std::string Provider(void) const = 0;

 protected:
  MappedRange(uint64_t base_address_, uint64_t limit_address_,
              const char *name_, uint64_t offset_);

  const uint64_t base_address;
  const uint64_t limit_address;

  // Mostly for debugging purposes.
  char name[256];
  const uint64_t offset;

 private:
  MappedRange(const MappedRange &) = delete;
  MappedRange(void) = delete;
};

}  // namespace vmill

#endif  // VMILL_MEMORY_MAPPEDRANGE_H_
