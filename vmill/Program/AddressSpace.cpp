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

#include <algorithm>
#include <iomanip>
#include <limits>
#include <new>

#include "remill/Arch/Arch.h"
#include "remill/OS/OS.h"

#include "vmill/Etc/xxHash/xxhash.h"
#include "vmill/Program/AddressSpace.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Util/Hash.h"

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

AddressSpace::AddressSpace(void)
    : invalid_map(MappedRange::CreateInvalid()),
      page_to_map(256),
      wnx_page_to_map(256),
      last_read_map(page_to_map.end()),
      last_written_map(wnx_page_to_map.end()),
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

// Have we observed a write to executable memory since our last attempt
// to read from executable memory?
bool AddressSpace::CodeVersionIsInvalid(void) const {
  return code_version_is_invalid;
}

// Returns a hash of all executable code. Useful for getting the current
// version of the code.
CodeVersion AddressSpace::ComputeCodeVersion(void) {
  if (unlikely(!CodeVersionIsInvalid())) {
    return static_cast<CodeVersion>(code_version);
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
        uint64_t map_code_version = map->ComputeCodeVersion();
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

  return static_cast<CodeVersion>(code_version);
}

void AddressSpace::MarkAsTraceHead(PC pc) {
  trace_heads.insert(static_cast<uint64_t>(pc));
}

bool AddressSpace::IsMarkedTraceHead(PC pc) const {
  return 0 != trace_heads.count(static_cast<uint64_t>(pc));
}

// Clear out the contents of this address space.
void AddressSpace::Kill(void) {
  maps.clear();
  page_to_map.clear();
  last_read_map = page_to_map.end();
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

bool AddressSpace::TryRead(uint64_t addr, void *val_out, size_t size) {
  auto out_stream = reinterpret_cast<uint8_t *>(val_out);
  for (auto page_addr = AlignDownToPage(addr),
            end_addr = addr + size;
       page_addr < end_addr;
       page_addr += kPageSize) {

    const auto &range = FindRange(page_addr);
    auto page_end_addr = page_addr + kPageSize;
    auto next_end_addr = std::min(end_addr, page_end_addr);
    while (addr < next_end_addr) {
      if (!range->Read(addr++, out_stream++)) {
        return false;
      }
    }
  }
  return true;
}

bool AddressSpace::TryWrite(uint64_t addr, const void *val, size_t size) {
  auto in_stream = reinterpret_cast<const uint8_t *>(val);
  for (auto page_addr = AlignDownToPage(addr),
            end_addr = addr + size;
       page_addr < end_addr;
       page_addr += kPageSize) {

    if (!CanWrite(page_addr)) {
      return false;
    }

    const auto &range = FindRange(page_addr);
    if (CanExecute(page_addr)) {
      range->InvalidateCodeVersion();

      if (!code_version_is_invalid) {
        LOG(INFO)
            << "Invalidating code version because of write to executable "
            << "memory at " << std::hex << addr << std::dec;
        code_version_is_invalid = true;
      }
    }

    auto page_end_addr = page_addr + kPageSize;
    auto next_end_addr = std::min(end_addr, page_end_addr);

    while (addr < next_end_addr) {
      if (!range->Write(addr++, *in_stream++)) {
        return false;
      }
    }
  }
  return true;
}

// Read/write a byte to memory.
bool AddressSpace::TryRead(uint64_t addr, uint8_t *val_out) {
  return FindRange(addr)->Read(addr, val_out);
}

#define MAKE_TRY_READ(type) \
    bool AddressSpace::TryRead(uint64_t addr, type *val_out) { \
      const auto &range = FindRange(addr); \
      auto out_stream = reinterpret_cast<uint8_t *>(val_out); \
      if (unlikely(!range->Read(addr, out_stream))) { \
        return false; \
      } \
      if (likely(range->BaseAddress() <= addr && \
                 (addr + sizeof(type)) <= range->LimitAddress())) { \
        _Pragma("unroll") \
        for (size_t i = 1; i < sizeof(type); ++i) { \
          (void) range->Read(addr + i, &(out_stream[i])); \
        } \
        return true; \
      } else { \
        return TryRead(addr, val_out, sizeof(type)); \
      } \
    }

MAKE_TRY_READ(uint16_t)
MAKE_TRY_READ(uint32_t)
MAKE_TRY_READ(uint64_t)
MAKE_TRY_READ(float)
MAKE_TRY_READ(double)

#undef MAKE_TRY_READ

bool AddressSpace::TryWrite(uint64_t addr, uint8_t val) {
  if (likely(FindWNXRange(addr)->Write(addr, val))) {
    return true;
  } else {
    return TryWrite(addr, &val, sizeof(val));
  }
}

#define MAKE_TRY_WRITE(type) \
    bool AddressSpace::TryWrite(uint64_t addr, type val) { \
      const auto &range = FindWNXRange(addr); \
      const auto out_stream = reinterpret_cast<const uint8_t *>(&val); \
      if (likely(range->Write(addr, out_stream[0]) && \
                 range->BaseAddress() <= addr && \
                 (addr + sizeof(type)) <= range->LimitAddress())) { \
        _Pragma("unroll") \
        for (size_t i = 1; i < sizeof(type); ++i) { \
          (void) range->Write(addr + i, out_stream[i]); \
        } \
        return true; \
      } else { \
        return TryWrite(addr, out_stream, sizeof(type)); \
      } \
    }


MAKE_TRY_WRITE(uint16_t)
MAKE_TRY_WRITE(uint32_t)
MAKE_TRY_WRITE(uint64_t)
MAKE_TRY_WRITE(float)
MAKE_TRY_WRITE(double)
#undef MAKE_TRY_WRITE

// Return the virtual address of the memory backing `addr`.
void *AddressSpace::ToVirtualAddress(uint64_t addr) {
  auto &range = FindRange(addr);
  return range->ToVirtualAddress(addr);
}

// Read a byte as an executable byte. This is used for instruction decoding.
bool AddressSpace::TryReadExecutable(PC pc, uint8_t *val) {
  auto addr = static_cast<uint64_t>(pc);
  auto &range = FindRange(addr);
  auto was_readable = range->Read(addr, val);
  if (likely(was_readable && CanExecute(addr))) {
    if (unlikely(code_version_is_invalid)) {
      (void) ComputeCodeVersion();
    }
    return true;
  } else {
    return false;
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

void AddressSpace::AddMap(uint64_t base_, size_t size, const char *name,
                          uint64_t offset) {
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

  auto new_map = MappedRange::Create(base, limit, name, offset);
  SetPermissions(base, (limit - base), true, true, false);

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

  last_read_map = page_to_map.end();
  last_written_map = wnx_page_to_map.end();

  page_to_map.clear();
  wnx_page_to_map.clear();

  auto old_read_size = page_to_map.size();
  auto old_write_size = wnx_page_to_map.size();

  std::sort(maps.begin(), maps.end(),
            [=] (const MemoryMapPtr &left, const MemoryMapPtr &right) {
    return left->BaseAddress() < right->BaseAddress();
  });

  page_to_map.reserve(old_read_size);
  wnx_page_to_map.reserve(old_write_size);

  for (const auto &map : maps) {
    for (auto addr = map->BaseAddress();
         addr < map->LimitAddress();
         addr += kPageSize) {

      if (page_is_readable.count(addr)) {
        page_to_map[addr] = map;
      }

      if (page_is_writable.count(addr) && !page_is_executable.count(addr)) {
        wnx_page_to_map[addr] = map;
      }
    }
  }
}

const MemoryMapPtr &AddressSpace::FindRange(uint64_t addr) {
  auto page_addr = AlignDownToPage(addr);
  if (likely(last_read_map != page_to_map.end() &&
             page_addr == last_read_map->first)) {
    return last_read_map->second;
  }

  last_read_map = page_to_map.find(page_addr);
  if (likely(last_read_map != page_to_map.end())) {
    return last_read_map->second;
  } else {
    return invalid_map;
  }
}

const MemoryMapPtr &AddressSpace::FindWNXRange(uint64_t addr) {
  auto page_addr = AlignDownToPage(addr);
  if (likely(last_written_map != wnx_page_to_map.end() &&
             page_addr == last_written_map->first)) {
    return last_written_map->second;
  }

  last_written_map = wnx_page_to_map.find(page_addr);
  if (likely(last_written_map != wnx_page_to_map.end())) {
    return last_written_map->second;
  } else {
    return invalid_map;
  }
}

// Log out the current state of the memory maps.
void AddressSpace::LogMaps(std::ostream &os) {
  os << "Memory maps:" << std::endl;
  for (const auto &range : maps) {
    std::stringstream ss;
    auto flags = ss.flags();
    ss << "  [" << std::hex << std::setw(16) << std::setfill('0')
       << range->BaseAddress() << ", " << std::hex << std::setw(16)
       << std::setfill('0') << range->LimitAddress() << ")";
    ss.setf(flags);

    auto virt = range->ToVirtualAddress(range->BaseAddress());
    if (virt) {
      ss << " at " << virt;
    }

    auto name = range->Name();
    auto offset = range->Offset();
    if (name && name[0]) {
      ss << " from " << name;
      if (offset) {
        ss << " (offset " << std::hex << offset << ")";
      }
    }

    os << ss.str() << std::endl;
  }
}

}  // namespace vmill
