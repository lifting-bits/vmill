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

#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <limits>
#include <new>

#include "remill/Arch/Arch.h"
#include "remill/OS/OS.h"

#include "vmill/Context/AddressSpace.h"
#include "vmill/Util/Hash.h"
#include "vmill/Etc/xxHash/xxhash.h"

namespace vmill {
namespace {

enum : uint64_t {
  kPageSize = 4096ULL,
  kPageShift = (kPageSize - 1ULL),
  kPageMask = ~kPageShift
};

static constexpr inline uint64_t AlignDownToPage(uint64_t addr) {
  return addr & kPageMask;
}

static constexpr inline uint64_t RoundUpToPage(uint64_t size) {
  return (size + kPageShift) & kPageMask;
}

}  // namespace

class ArrayMemoryMap;
class EmptyMemoryMap;
class CopyOnWriteMemoryMap;

// Basic information about some region of mapped memory within an address space.
class MemoryMap {
 public:
  MemoryMap(uint64_t base_address_, uint64_t limit_address_);

  virtual ~MemoryMap(void);

  inline uint64_t BaseAddress(void) const {
    return base_address;
  }

  inline uint64_t LimitAddress(void) const {
    return limit_address;
  }

  inline uint64_t Size(void) const {
    return limit_address - base_address;
  }

  inline bool Contains(uint64_t address) const {
    return base_address <= address && address < limit_address;
  }

  static bool LessThan(const MemoryMapPtr &left, const MemoryMapPtr &right) {
    return left->BaseAddress() < right->BaseAddress();
  }

  inline void InvalidateCodeVersion(void) {
    code_version_is_valid = false;
  }

  virtual uint8_t Read(uint64_t address) = 0;

  virtual void Write(uint64_t address, uint8_t val) = 0;

  virtual MemoryMapPtr Clone(void) = 0;

  virtual uint64_t CodeVersion(void) = 0;

  MemoryMapPtr Copy(uint64_t clone_base, uint64_t clone_limit);

 protected:
  const uint64_t base_address;
  const uint64_t limit_address;
  uint64_t code_version;
  bool code_version_is_valid;

  uint8_t *data;
  MemoryMapPtr parent;

 private:
  friend class ArrayMemoryMap;
  friend class EmptyMemoryMap;
  friend class CopyOnWriteMemoryMap;

  MemoryMap(const MemoryMap &) = delete;
  MemoryMap(void) = delete;
};

MemoryMap::MemoryMap(uint64_t base_address_, uint64_t limit_address_)
    : base_address(base_address_),
      limit_address(limit_address_),
      code_version(0),
      code_version_is_valid(false),
      data(nullptr),
      parent(nullptr) {}

MemoryMap::~MemoryMap(void) {
  if (data) {
    delete [] data;
    data = nullptr;
  }
}

// Implements an array-backed memory mapping that is filled with actual data
// bytes.
class ArrayMemoryMap : public MemoryMap {
 public:
  ArrayMemoryMap(uint64_t base_address_, uint64_t limit_address_)
      : MemoryMap(base_address_, limit_address_) {
    data = new uint8_t[Size()];
    memset(data, 0, Size());
  }

  explicit ArrayMemoryMap(MemoryMap *steal)
      : MemoryMap(steal->base_address, steal->limit_address) {
    data = steal->data;
    steal->data = nullptr;
  }

  uint8_t Read(uint64_t address) override {
    return data[address - base_address];
  }

  void Write(uint64_t address, uint8_t val) override {
    data[address - BaseAddress()] = val;
  }

  MemoryMapPtr Clone(void) override;

  uint64_t CodeVersion(void) override;
};

static_assert(sizeof(ArrayMemoryMap) == sizeof(MemoryMap),
              "Vtable overwriting won't work!");

// Implements an empty range of memory that is filled with zeroes.
class EmptyMemoryMap : public MemoryMap {
 public:
  using MemoryMap::MemoryMap;

  virtual ~EmptyMemoryMap(void) {}

  uint8_t Read(uint64_t) override {
    return 0;
  }

  void Write(uint64_t address, uint8_t val) override {
    auto self = (new (this) ArrayMemoryMap(base_address, limit_address));
    self->Write(address, val);
  }

  MemoryMapPtr Clone(void) override {
    return std::make_shared<EmptyMemoryMap>(base_address, limit_address);
  }

  uint64_t CodeVersion(void) override {
    return 0;
  }
};

static_assert(sizeof(EmptyMemoryMap) == sizeof(MemoryMap),
              "Vtable overwriting won't work!");

// Implements a copy-on-write range of memory.
class CopyOnWriteMemoryMap : public MemoryMap {
 public:
  explicit CopyOnWriteMemoryMap(MemoryMapPtr parent_)
      : MemoryMap(parent_->base_address, parent_->limit_address) {
    while (parent_) {
      parent = parent_;
      parent_ = parent->parent;
    }
  }

  uint8_t Read(uint64_t address) override {
    return parent->Read(address);
  }

  void Write(uint64_t address, uint8_t val) override {
    auto parent_ptr = parent;
    auto base_addr = BaseAddress();
    auto limit_addr = LimitAddress();
    parent.reset();
    auto self = new (this) ArrayMemoryMap(base_addr, limit_addr);
    for (uint64_t index = 0; base_addr < limit_addr; ++base_addr, ++index) {
      self->data[index] = parent_ptr->Read(base_addr);
    }
  }

  MemoryMapPtr Clone(void) override {
    return std::make_shared<CopyOnWriteMemoryMap>(parent);
  }

  uint64_t CodeVersion(void) override {
    return parent->CodeVersion();
  }

 private:
  using MemoryMap::MemoryMap;
};

static_assert(sizeof(CopyOnWriteMemoryMap) == sizeof(MemoryMap),
              "Vtable overwriting won't work!");

// Creates a new `ArrayMemoryMap` that takes over the data of this array memory
// map, then we convert this array memory map into a copy-on-write memory map,
// and then clone it.
MemoryMapPtr ArrayMemoryMap::Clone(void) {
  auto parent = std::make_shared<ArrayMemoryMap>(this);
  auto self = new (this) CopyOnWriteMemoryMap(parent);
  return self->Clone();
}

MemoryMapPtr MemoryMap::Copy(uint64_t clone_base, uint64_t clone_limit) {
  auto array_backed = std::make_shared<ArrayMemoryMap>(clone_base, clone_limit);
  for (; clone_base < clone_limit; ++clone_base) {
    if (Contains(clone_base)) {
      array_backed->Write(clone_base, Read(clone_base));
    }
  }
  return array_backed;
}

uint64_t ArrayMemoryMap::CodeVersion(void) {
  if (code_version_is_valid) {
    return code_version;
  }

  XXH64_state_t state = {};
  XXH64_reset(&state, 0);
  XXH64_update(&state, data, Size());
  code_version = XXH64_digest(&state);
  code_version_is_valid = true;
  return code_version;
}

AddressSpace::AddressSpace(void)
    : invalid_map(std::make_shared<EmptyMemoryMap>(0, 0)),
      page_to_map(256),
      is_dead(false),
      code_version_is_invalid(true),
      code_version(0) {
  CreatePageToRangeMap();
}

AddressSpace::AddressSpace(const AddressSpace &parent)
    : invalid_map(parent.invalid_map),
      maps(parent.maps.size()),
      page_to_map(parent.page_to_map.size()),
      is_dead(parent.is_dead),
      code_version_is_invalid(parent.code_version_is_invalid),
      code_version(parent.code_version) {

  unsigned i = 0;
  for (const auto &range : parent.maps) {
    maps[i++] = range->Clone();
  }

  CreatePageToRangeMap();
}

AddressSpace::AddressSpace(const AddressSpacePtr &parent_ptr)
    : AddressSpace(*parent_ptr) {}

// Have we observed a write to executable memory since our last attempt
// to read from executable memory?
bool AddressSpace::CodeVersionIsInvalid(void) const {
  return code_version_is_invalid;
}

// Returns a hash of all executable code. Useful for getting the current
// version of the code.
uint64_t AddressSpace::CodeVersion(void) {
  if (!CodeVersionIsInvalid()) {
    return code_version;
  }

  trace_heads.clear();

  XXH64_state_t state = {};
  XXH64_reset(&state, 0);

  auto num_maps = 0;
  for (auto &map : this->maps) {
    auto addr = map->BaseAddress();
    auto limit_addr = map->LimitAddress();
    for (; addr < limit_addr; addr += kPageSize) {
      if (CanExecute(addr)) {
        num_maps += 1;
        uint64_t map_code_version = map->CodeVersion();
        XXH64_update(&state, &map_code_version, sizeof(map_code_version));
        break;
      }
    }
  }

  code_version = XXH64_digest(&state);
  code_version_is_invalid = false;

  LOG(INFO)
      << "New code version " << std::hex << code_version << " is a hash of "
      << std::dec << num_maps << " memory maps";

  return code_version;
}

void AddressSpace::MarkAsTraceHead(uint64_t pc) {
  trace_heads.insert(pc);
}

bool AddressSpace::IsMarkedTraceHead(uint64_t pc) const {
  return 0 != trace_heads.count(pc);
}

// Clear out the contents of this address space.
void AddressSpace::Kill(void) {
  maps.clear();
  page_to_map.clear();
  last_mapped_page = page_to_map.end();
  is_dead = true;
}

// Returns `true` if this address space is "dead".
bool AddressSpace::IsDead(void) const {
  return is_dead;
}

bool AddressSpace::CanRead(uint64_t addr) const {
  return page_is_readable.count(AlignDownToPage(addr));
}

bool AddressSpace::CanWrite(uint64_t addr) const {
  return page_is_writable.count(AlignDownToPage(addr));
}

bool AddressSpace::CanExecute(uint64_t addr) const {
  return page_is_executable.count(AlignDownToPage(addr));
}

// Read/write a byte to memory.
bool AddressSpace::TryRead(uint64_t addr, uint8_t *val) {
  if (likely(CanRead(addr))) {
    const auto &range = FindRange(addr);
    *val = range->Read(addr);
    return true;
  } else {
    return false;
  }
}

bool AddressSpace::TryWrite(uint64_t addr, uint8_t val) {
  if (likely(CanWrite(addr))) {
    const auto &range = FindRange(addr);
    if (unlikely(CanExecute(addr))) {
      if (!code_version_is_invalid) {
        LOG(INFO)
            << "Invalidating code version because of write to executable "
            << "memory at " << std::hex << addr << std::dec;
        code_version_is_invalid = true;
        range->InvalidateCodeVersion();
      }
    }
    range->Write(addr, val);
    return true;
  } else {
    return false;
  }
}

// Read a byte as an executable byte. This is used for instruction decoding.
bool AddressSpace::TryReadExecutable(uint64_t addr, uint8_t *val) {
  if (!CanRead(addr) || !CanExecute(addr)) {
    return false;
  } else {
    if (code_version_is_invalid) {
      (void) CodeVersion();
    }
    code_version_is_invalid = false;
    *val = FindRange(addr)->Read(addr);
    return true;
  }
}

namespace {

// Return a vector of memory maps, where none of the maps overlap with the
// range of memory `[base, limit)`.
static std::vector<MemoryMapPtr> RemoveRange(
    const std::vector<MemoryMapPtr> &ranges, uint64_t base, uint64_t limit) {

  std::vector<MemoryMapPtr> new_ranges;
  new_ranges.reserve(ranges.size() + 1);

  DLOG(INFO)
      << "  RemoveRange: [" << std::hex << base << ", "
      << std::hex << limit << ")";

  for (auto &map : ranges) {

    auto map_base_address = map->BaseAddress();
    auto map_limit_address = map->LimitAddress();

    // No overlap between `map` and the range to remove.
    if (map_limit_address <= base || map_base_address >= limit) {
      DLOG(INFO)
          << "    Keeping with no overlap ["
          << std::hex << map_base_address << ", "
          << std::hex << map_limit_address << ")";
      new_ranges.push_back(map);

    // `map` is fully contained in the range to remove.
    } else if (map_base_address >= base && map_limit_address <= limit) {
      DLOG(INFO)
          << "    Removing with full containment ["
          << std::hex << map_base_address << ", "
          << std::hex << map_limit_address << ")";
      continue;

    // The range to remove is fully contained in `map`.
    } else if (map_base_address < base && map_limit_address > limit) {
      DLOG(INFO)
          << "    Splitting with overlap ["
          << std::hex << map->BaseAddress() << ", "
          << std::hex << map_limit_address << ") into "
          << "[" << std::hex << map_base_address << ", "
          << std::hex << base << ") and ["
          << std::hex << limit << ", " << std::hex << map_limit_address << ")";

      new_ranges.push_back(map->Copy(map_base_address, base));
      new_ranges.push_back(map->Copy(limit, map_limit_address));

    // The range to remove is a prefix of `map`.
    } else if (map_base_address == base) {
      DLOG(INFO)
          << "    Keeping prefix [" << std::hex << limit << ", "
          << std::hex << map_limit_address << ")";
      new_ranges.push_back(map->Copy(limit, map_limit_address));

    // The range to remove is a suffix of `map`.
    } else {
      DLOG(INFO)
          << "    Keeping suffix ["
          << std::hex << map_base_address << ", "
          << std::hex << base << ")";
      new_ranges.push_back(map->Copy(map_base_address, base));
    }
  }

  return new_ranges;
}

}  // namespace

void AddressSpace::SetPermissions(uint64_t base_, size_t size, bool can_read,
                                  bool can_write, bool can_exec) {
  auto base = AlignDownToPage(base_);
  auto limit = base + RoundUpToPage(size);

  auto seen_exec = false;
  auto seen_non_exec = false;

  for (auto addr = base; addr < limit; addr += kPageSize) {
    page_is_readable.erase(addr);
    page_is_writable.erase(addr);

    if (page_is_executable.count(addr)) {
      seen_exec = true;
      page_is_executable.erase(addr);
    } else {
      seen_non_exec = true;
    }

    if (can_read) {
      page_is_readable.insert(addr);
    }
    if (can_write) {
      page_is_writable.insert(addr);
    }
    if (can_exec) {
      page_is_executable.insert(addr);
    }
  }

  if (!code_version_is_invalid) {
    if (can_exec && seen_non_exec) {
      code_version_is_invalid = true;
    }

    if (!can_exec && seen_exec) {
      code_version_is_invalid = true;
    }

    if (code_version_is_invalid) {
      LOG(INFO)
          << "Invalidating code version because of change of permissions "
          << "of memory [" << std::hex << base << ", " << limit
          << ")" << std::dec;
    }
  }
}

void AddressSpace::AddMap(uint64_t base_, size_t size,
                          bool can_read, bool can_write, bool can_exec) {
  auto base = AlignDownToPage(base_);
  auto limit = base + RoundUpToPage(size);

  if (is_dead) {
    LOG(ERROR)
        << "Trying to map range [" << std::hex << base << ", " << limit
        << ") in destroyed address space." << std::dec;
    return;
  }

  LOG(INFO)
      << "Mapping range [" << std::hex << base << ", " << limit
      << ")" << std::dec;

  auto old_ranges = RemoveRange(maps, base, limit);
  CheckRanges(old_ranges);

  if (old_ranges.size() < maps.size()) {
    LOG(INFO)
        << "New map [" << std::hex << base << ", " << limit << ")"
        << " overlapped with " << std::dec << (maps.size() - old_ranges.size())
        << " existing maps";
  }

  auto new_map = std::make_shared<EmptyMemoryMap>(base, limit);
  SetPermissions(base, (limit - base), can_read, can_write, can_exec);

  maps.swap(old_ranges);
  maps.push_back(new_map);

  CheckRanges(maps);
  CreatePageToRangeMap();
}

void AddressSpace::RemoveMap(uint64_t base_, size_t size) {
  auto base = AlignDownToPage(base_);
  auto limit = base + RoundUpToPage(size);

  LOG(INFO)
      << "Unmapping range [" << std::hex << base << ", "
      << limit << ")" << std::dec;

  if (is_dead) {
    LOG(ERROR)
        << "Trying to unmap range ["
        << std::hex << base << ", " << std::hex << limit
        << ") in destroyed address space.";
    return;
  }

  maps = RemoveRange(maps, base, limit);

  for (; base < limit; base += kPageSize) {
    if (page_is_executable.count(base)) {
      if (!code_version_is_invalid) {
        code_version_is_invalid = true;
        LOG(INFO)
          << "Invalidating code version because of removal of executable page "
          << "at " << std::hex << base << std::dec;
      }
      page_is_executable.erase(base);
    }

    page_is_readable.erase(base);
    page_is_writable.erase(base);
  }

  CheckRanges(maps);
  CreatePageToRangeMap();
}

// Find the smallest mapped memory range limit address that is greater
// than `find`.
//
// TODO(pag): Optimize this.
bool AddressSpace::NearestLimitAddress(
    uint64_t find, uint64_t *next_end) const {
  if (is_dead) {
    LOG(ERROR)
        << "Trying to query nearest limit address of "
        << std::hex << find << " in destroyed address space"
        << std::dec;
    return false;
  }

  for (const auto &map : maps) {
    auto limit_address = map->LimitAddress();
    if (find < limit_address) {
      *next_end = limit_address;
      return true;
    }
  }

  *next_end = 0;
  return false;
}

// Find the largest mapped memory range base address that is less-than
// or equal to `find`.
//
// TODO(pag): Optimize this.
bool AddressSpace::NearestBaseAddress(
    uint64_t find, uint64_t *prev_begin) const {
  if (is_dead) {
    LOG(ERROR)
        << "Trying to query nearest base address of "
        << std::hex << find << " in destroyed address space"
        << std::dec;
    return false;
  }

  *prev_begin = 0;
  auto found = false;
  for (const auto &map : maps) {
    auto base_address = map->BaseAddress();
    if (base_address <= find) {
      *prev_begin = base_address;
      found = true;
    } else {
      break;
    }
  }
  return found;
}

// Check that the ranges are sane.
void AddressSpace::CheckRanges(std::vector<MemoryMapPtr> &r) {
#ifndef NDEBUG

  if (1 >= r.size()) {
    return;  // Trivially sorted.
  }

  auto it = r.begin();
  auto it_end = r.end() - 1;

  for (; it != it_end; ) {
    const auto &curr = *it;
    const auto &next = *++it;

    CHECK(curr->BaseAddress() < curr->LimitAddress())
        << "Invalid range bounds [" << std::hex << curr->BaseAddress() << ", "
        << std::hex << curr->LimitAddress() << ")";

    CHECK(curr->LimitAddress() <= next->BaseAddress())
          << "Overlapping ranges [" << std::hex << curr->BaseAddress() << ", "
          << std::hex << curr->LimitAddress() << ") and ["
          << std::hex << next->BaseAddress() << ", "
          << std::hex << next->LimitAddress() << ")";
  }
#endif

  (void) r;  // Mark as used.
}

void AddressSpace::CreatePageToRangeMap(void) {
  last_mapped_page = page_to_map.end();

  auto old_size = page_to_map.size();
  page_to_map.clear();

  std::sort(maps.begin(), maps.end(),
            [=] (const MemoryMapPtr &left, const MemoryMapPtr &right) {
    return left->BaseAddress() < right->BaseAddress();
  });

  page_to_map.reserve(old_size);
  for (const auto &map : maps) {
    for (auto addr = map->BaseAddress();
         addr < map->LimitAddress();
         addr += kPageSize) {
      page_to_map[addr] = map;
    }
  }

}

const MemoryMapPtr &AddressSpace::FindRange(uint64_t addr) {
  if (unlikely(is_dead)) {
    return invalid_map;
  }

  auto page_addr = AlignDownToPage(addr);
  if (last_mapped_page != page_to_map.end() &&
      page_addr == last_mapped_page->first) {
    return last_mapped_page->second;
  }

  last_mapped_page = page_to_map.find(page_addr);
  if (last_mapped_page == page_to_map.end()) {
    return invalid_map;
  } else {
    return last_mapped_page->second;
  }
}

// Log out the current state of the memory maps.
void AddressSpace::LogMaps(void) {
  LOG(INFO)
      << "Memory maps:";
  for (const auto &range : maps) {
    LOG(INFO)
        << "  [" << std::hex << range->BaseAddress() << ", "
        << std::hex << range->LimitAddress() << ")";
  }
}

}  // namespace vmill
