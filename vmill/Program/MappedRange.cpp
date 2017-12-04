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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <limits>
#include <map>
#include <memory>
#include <new>
#include <utility>
#include <vector>

#include "vmill/Program/MappedRange.h"
#include "vmill/Util/AreaAllocator.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Util/Hash.h"

namespace vmill {
namespace {

enum : uint64_t {
  kPageSize = 4096ULL,
  kPageShift = (kPageSize - 1ULL),
  kPageMask = ~kPageShift
};

class MappedRangeBase;
class ArrayMemoryMap;
class EmptyMemoryMap;
class CopyOnWriteMemoryMap;
class InvalidMemoryMap;

struct Allocation {
  uint8_t *base;
  size_t size;

  inline void Reset(void) {
    base = nullptr;
    size = 0;
  }
};

class ArrayMemoryAllocator {
 public:
  ArrayMemoryAllocator(void)
      : allocator(kAreaRW, kAreaAddressSpace) {}

  Allocation Allocate(size_t size) {

    Allocation alloc = {};
    auto lb = free_list.lower_bound(size);
    if (lb != free_list.end() && !lb->second.empty()) {
      alloc.base = lb->second.back();
      alloc.size = lb->first;
      lb->second.pop_back();

      if (alloc.size != size) {
        CHECK(alloc.size >= size);


        auto diff = alloc.size - size;
        if (diff > kPageSize) {
          LOG(INFO)
              << "Splitting previously freed " << std::hex << alloc.size
              << "-byte allocation for a " << size << "-byte allocation"
              << std::dec;

          Allocation split = {alloc.base, diff};
          Free(split);

          alloc.base = &(alloc.base[diff]);
          alloc.size = size;
        } else {
          LOG(INFO)
              << "Re-using a previously freed " << std::hex << alloc.size
              << "-byte allocation for a " << size << "-byte allocation"
              << std::dec;
        }
      }

    } else {
      alloc.base = allocator.Allocate(size, 64  /* Cache line size */);
      alloc.size = size;
    }

    memset(alloc.base, 0, size);
    return alloc;
  }

  void Free(Allocation &alloc) {
    if (alloc.base) {
      free_list[alloc.size].push_back(alloc.base);
      alloc.Reset();
    }
  }

  AreaAllocator allocator;
  std::map<size_t, std::vector<uint8_t *>> free_list;
};


// Basic information about some region of mapped memory within an address space.
class MappedRangeBase : public MappedRange {
 public:
  MappedRangeBase(uint64_t base_address_, uint64_t limit_address_,
                  const char *name_, uint64_t offset_);
  virtual ~MappedRangeBase(void);
  virtual bool IsValid(void) const;
  void InvalidateCodeVersion(void) final;
  MemoryMapPtr Copy(uint64_t clone_base, uint64_t clone_limit) final;

  CodeVersion code_version;
  bool code_version_is_valid;
  Allocation data;
  MemoryMapPtr parent;
};

// Implements an invalid range of memory that is unfilled.
class InvalidMemoryMap : public MappedRangeBase {
 public:
  using MappedRangeBase::MappedRangeBase;

  virtual ~InvalidMemoryMap(void);
  bool Read(uint64_t, uint8_t *out_val) final;
  bool Write(uint64_t, uint8_t) final;
  MemoryMapPtr Clone(void) final;
  CodeVersion ComputeCodeVersion(void) final;
  bool IsValid(void) const final;
};

// Implements an array-backed memory mapping that is filled with actual data
// bytes.
class ArrayMemoryMap : public MappedRangeBase {
 public:
  ArrayMemoryMap(uint64_t base_address_, uint64_t limit_address_,
                 const char *name_, uint64_t offset_);


  explicit ArrayMemoryMap(ArrayMemoryMap *steal);

  virtual ~ArrayMemoryMap(void);

  bool Read(uint64_t address, uint8_t *out_val) final;
  bool Write(uint64_t address, uint8_t val) final;
  MemoryMapPtr Clone(void) final;
  CodeVersion ComputeCodeVersion(void) final;
  void *ToReadWriteVirtualAddress(uint64_t addr) final;
  const void *ToReadOnlyVirtualAddress(uint64_t addr) final;

  static ArrayMemoryAllocator allocator;
};

// Implements an empty range of memory that is filled with zeroes.
class EmptyMemoryMap : public MappedRangeBase {
 public:
  using MappedRangeBase::MappedRangeBase;

  virtual ~EmptyMemoryMap(void);
  bool Read(uint64_t, uint8_t *out_val) final;
  bool Write(uint64_t address, uint8_t val) final;
  MemoryMapPtr Clone(void) final;
  CodeVersion ComputeCodeVersion(void) final;
  void *ToReadWriteVirtualAddress(uint64_t addr) final;
  const void *ToReadOnlyVirtualAddress(uint64_t addr) final;
};

// Implements a copy-on-write range of memory.
class CopyOnWriteMemoryMap : public MappedRangeBase {
 public:
  explicit CopyOnWriteMemoryMap(MemoryMapPtr parent_);
  virtual ~CopyOnWriteMemoryMap(void);
  bool IsValid(void) const final;
  bool Read(uint64_t address, uint8_t *out_val) final;
  bool Write(uint64_t address, uint8_t val) final;
  MemoryMapPtr Clone(void) final;
  CodeVersion ComputeCodeVersion(void) final;
  void *ToReadWriteVirtualAddress(uint64_t addr) final;
  const void *ToReadOnlyVirtualAddress(uint64_t addr) final;

 private:
  using MappedRangeBase::MappedRangeBase;
};

static_assert(sizeof(ArrayMemoryMap) == sizeof(MappedRangeBase),
              "Vtable overwriting won't work!");

static_assert(sizeof(EmptyMemoryMap) == sizeof(MappedRangeBase),
              "Vtable overwriting won't work!");

static_assert(sizeof(InvalidMemoryMap) == sizeof(MappedRangeBase),
              "Vtable overwriting won't work!");

static_assert(sizeof(CopyOnWriteMemoryMap) == sizeof(MappedRangeBase),
              "Vtable overwriting won't work!");

MappedRangeBase::MappedRangeBase(
    uint64_t base_address_, uint64_t limit_address_,
    const char *name_, uint64_t offset_)
    : MappedRange(base_address_, limit_address_, name_, offset_),
      code_version(static_cast<CodeVersion>(0)),
      code_version_is_valid(false),
      data{nullptr, 0},
      parent(nullptr) {}

MappedRangeBase::~MappedRangeBase(void) {
  CHECK(!data.base);
}

void MappedRangeBase::InvalidateCodeVersion(void) {
  code_version_is_valid = false;
}

bool MappedRangeBase::IsValid(void) const {
  return true;
}

MemoryMapPtr MappedRangeBase::Copy(uint64_t clone_base, uint64_t clone_limit) {
  auto array_backed = std::make_shared<ArrayMemoryMap>(
      clone_base, clone_limit,
      Name(), Offset() + (clone_base - BaseAddress()));

  for (; clone_base < clone_limit; ++clone_base) {
    if (Contains(clone_base)) {
      uint8_t val = 0;
      Read(clone_base, &val);
      array_backed->Write(clone_base, val);
    }
  }
  return array_backed;
}


InvalidMemoryMap::~InvalidMemoryMap(void) {}

bool InvalidMemoryMap::Read(uint64_t, uint8_t *out_val) {
  *out_val = 0;
  return false;
}

bool InvalidMemoryMap::Write(uint64_t, uint8_t) {
  return false;
}

MemoryMapPtr InvalidMemoryMap::Clone(void) {
  return std::make_shared<InvalidMemoryMap>(BaseAddress(), LimitAddress(),
                                            Name(), Offset());
}

CodeVersion InvalidMemoryMap::ComputeCodeVersion(void) {
  return static_cast<CodeVersion>(0);
}

bool InvalidMemoryMap::IsValid(void) const {
  return false;
}

ArrayMemoryAllocator ArrayMemoryMap::allocator;

// Allocate memory for some data. This will redzone the allocation with
// two unreadable/unwritable pages around the allocation.
ArrayMemoryMap::ArrayMemoryMap(uint64_t base_address_, uint64_t limit_address_,
                               const char *name_, uint64_t offset_)
    : MappedRangeBase(base_address_, limit_address_, name_, offset_) {

  CHECK(Size() == (Size() / kPageSize) * kPageSize)
      << "Invalid memory map size.";

  data = allocator.Allocate(Size());
}

ArrayMemoryMap::ArrayMemoryMap(ArrayMemoryMap *steal)
    : MappedRangeBase(steal->BaseAddress(), steal->LimitAddress(),
                      steal->Name(), steal->Offset()) {
  data = steal->data;
  steal->data.Reset();
}

ArrayMemoryMap::~ArrayMemoryMap(void) {
  allocator.Free(data);
}

bool ArrayMemoryMap::Read(uint64_t address, uint8_t *out_val) {
  *out_val = data.base[address - base_address];
  return true;
}

bool ArrayMemoryMap::Write(uint64_t address, uint8_t val) {
  data.base[address - BaseAddress()] = val;
  return true;
}

// Creates a new `ArrayMemoryMap` that takes over the data of this array memory
// map, then we convert this array memory map into a copy-on-write memory map,
// and then clone it.
MemoryMapPtr ArrayMemoryMap::Clone(void) {
  auto parent = std::make_shared<ArrayMemoryMap>(this);
  auto self = new (this) CopyOnWriteMemoryMap(parent);
  return self->Clone();
}

CodeVersion ArrayMemoryMap::ComputeCodeVersion(void) {
  if (code_version_is_valid) {
    return code_version;
  }
  code_version = static_cast<CodeVersion>(Hash(data.base, Size()));
  code_version_is_valid = true;
  return code_version;
}

void *ArrayMemoryMap::ToReadWriteVirtualAddress(uint64_t address) {
  return &(data.base[address - base_address]);
}

const void *ArrayMemoryMap::ToReadOnlyVirtualAddress(uint64_t address) {
  return &(data.base[address - base_address]);
}

EmptyMemoryMap::~EmptyMemoryMap(void) {}

bool EmptyMemoryMap::Read(uint64_t, uint8_t *out_val) {
  *out_val = 0;
  return true;
}

bool EmptyMemoryMap::Write(uint64_t address, uint8_t val) {
  auto byte_ptr = ToReadWriteVirtualAddress(address);
  *reinterpret_cast<uint8_t *>(byte_ptr) = val;
  return true;
}

MemoryMapPtr EmptyMemoryMap::Clone(void) {
  return std::make_shared<EmptyMemoryMap>(BaseAddress(), LimitAddress(),
                                          Name(), Offset());
}

CodeVersion EmptyMemoryMap::ComputeCodeVersion(void) {
  return static_cast<CodeVersion>(0);
}

void *EmptyMemoryMap::ToReadWriteVirtualAddress(uint64_t addr) {
  auto self = new (this) ArrayMemoryMap(BaseAddress(), LimitAddress(),
                                        Name(), Offset());
  return self->ToReadWriteVirtualAddress(addr);
}

static const uint8_t kZeroes[512 / 8] = {};

const void *EmptyMemoryMap::ToReadOnlyVirtualAddress(uint64_t addr) {
  return &(kZeroes[0]);
}

CopyOnWriteMemoryMap::CopyOnWriteMemoryMap(MemoryMapPtr parent_)
    : MappedRangeBase(parent_->BaseAddress(), parent_->LimitAddress(),
                      parent_->Name(), parent_->Offset()) {
  while (parent_) {
    parent = parent_;
    parent_ = reinterpret_cast<MappedRangeBase &>(*parent).parent;
  }
}

CopyOnWriteMemoryMap::~CopyOnWriteMemoryMap(void) {}

bool CopyOnWriteMemoryMap::IsValid(void) const {
  return parent->IsValid();
}

bool CopyOnWriteMemoryMap::Read(uint64_t address, uint8_t *out_val) {
  return parent->Read(address, out_val);
}

bool CopyOnWriteMemoryMap::Write(uint64_t address, uint8_t val) {
  auto byte_ptr = ToReadWriteVirtualAddress(address);
  *reinterpret_cast<uint8_t *>(byte_ptr) = val;
  return true;
}

MemoryMapPtr CopyOnWriteMemoryMap::Clone(void) {
  return std::make_shared<CopyOnWriteMemoryMap>(parent);
}

CodeVersion CopyOnWriteMemoryMap::ComputeCodeVersion(void) {
  return parent->ComputeCodeVersion();
}

void *CopyOnWriteMemoryMap::ToReadWriteVirtualAddress(uint64_t address) {
  auto parent_ptr = parent;
  auto base_addr = BaseAddress();
  auto limit_addr = LimitAddress();

  parent.reset();

  auto self = new (this) ArrayMemoryMap(base_addr, limit_addr,
                                        parent_ptr->Name(), Offset());
  for (uint64_t index = 0; base_addr < limit_addr; ++base_addr, ++index) {
    (void) parent_ptr->Read(base_addr, &(self->data.base[index]));
  }
  return self->ToReadWriteVirtualAddress(address);
}

const void *CopyOnWriteMemoryMap::ToReadOnlyVirtualAddress(uint64_t address) {
  return parent->ToReadOnlyVirtualAddress(address);
}

}  // namespace

MemoryMapPtr MappedRange::Create(uint64_t base_address_,
                                 uint64_t limit_address_,
                                 const char *name_,
                                 uint64_t offset_) {
  MemoryMapPtr ptr(new EmptyMemoryMap(base_address_, limit_address_,
                                      name_, offset_));
  return ptr;
}

MemoryMapPtr MappedRange::CreateInvalidLow(void) {
  MemoryMapPtr ptr(new InvalidMemoryMap(0, 0, "low tombstone", 0));
  return ptr;
}

MemoryMapPtr MappedRange::CreateInvalidHigh(void) {
  auto max = std::numeric_limits<uint64_t>::max();
  MemoryMapPtr ptr(new InvalidMemoryMap(max, max, "high tombstone", 0));
  return ptr;
}

MappedRange::MappedRange(uint64_t base_address_, uint64_t limit_address_,
                         const char *name_, uint64_t offset_)
    : base_address(base_address_),
      limit_address(limit_address_),
      offset(offset_) {
  if (!name_) {
    name[0] = '\0';
  } else if (name_ != &(name[0])) {
    strncpy(&(name[0]), name_, sizeof(name));
    name[sizeof(name) - 1] = '\0';
  }
}

MappedRange::~MappedRange(void) {}

// Return the virtual address of the memory backing `addr`.
void *MappedRange::ToReadWriteVirtualAddress(uint64_t) {
  return nullptr;
}

// Return the virtual address of the memory backing `addr`.
const void *MappedRange::ToReadOnlyVirtualAddress(uint64_t) {
  return nullptr;
}

}  // namespace vmill
