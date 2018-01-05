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

#include <glog/logging.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <sys/mman.h>
#include <unistd.h>

#include "vmill/Program/ShadowMemory.h"

extern "C" {
void arch_sys_sigreturn(void);  // Defined in `Arch/*/Signal.S`.
}  // extern C

namespace vmill {
namespace {

struct SaveErrno {
  int no;
  SaveErrno(void)
      : no(errno) {}
  ~SaveErrno(void) {
    errno = no;
  }
};

static ShadowMemory *gShadowMem = nullptr;

static struct sigaction gPrevSignalHandler = {};

//static SignalFuncType *gPrevSignalHandler = nullptr;

static void CatchFault(int sig, siginfo_t *si, void *context) {
  SaveErrno save_errno;

  if (gShadowMem) {
    auto addr = reinterpret_cast<uint64_t>(si->si_addr);
    if (gShadowMem->AddPageForAddress(addr)) {
      return;
    }
  }

  if (gPrevSignalHandler.sa_sigaction) {
    gPrevSignalHandler.sa_sigaction(sig, si, context);
    if (gPrevSignalHandler.sa_restorer) {
      return;  // This isn't exactly right.
    }
  }
  abort();
}

static uint64_t GreatestCommonDivisor(uint64_t k, uint64_t m) {
  while (k != m) {
    if (k > m) {
      k = k - m;
    } else {
      m = m - k;
    }
  }
  return k;
}

static uint64_t LeastCommonMultiple(uint64_t k, uint64_t m) {
  return (k * m) / GreatestCommonDivisor(k, m);
}

}  // namespace

std::unique_ptr<ShadowMemory> ShadowMemory::Get(
    uint64_t shadow_granularity_, uint64_t page_granularity_,
    uint64_t shadow_base_) {

  CHECK(!gShadowMem)
      << "There can only be one active instance of shadow memory at a time.";

  struct sigaction act;
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = CatchFault;
  act.sa_restorer = arch_sys_sigreturn;
  sigfillset(&(act.sa_mask));

  if (-1 == ::sigaction(SIGSEGV, &act, &gPrevSignalHandler)) {
    auto err = errno;
    LOG(FATAL)
        << "Can't catch SIGSEGV for shadow memory: " << strerror(err);
  }

  gShadowMem = new ShadowMemory(shadow_granularity_, page_granularity_,
                                shadow_base_);

  return std::unique_ptr<ShadowMemory>(gShadowMem);
}

void ShadowMemory::Put(std::unique_ptr<ShadowMemory> &mem) {
  mem.reset(nullptr);
}

ShadowMemory::ShadowMemory(uint64_t shadow_granularity_,
                           uint64_t page_granularity_,
                           uint64_t shadow_base_)
    : shadow_granularity(shadow_granularity_),
      shadow_base(shadow_base_),
      page_granularity(page_granularity_),
      last_shadow_address(0),
      last_shadow_elem_size_bits(0),
      last_forced_shadow_byte(0),
      last_shadow_page_size(0),
      out_of_range_allocator(kAreaRW, 0, 4096) {

  out_of_range.reserve(4096);
  shadow_pages.reserve(4096);
}

ShadowMemory *ShadowMemory::Self(void) {
  return gShadowMem;
}

ShadowMemory::~ShadowMemory(void) {
  CHECK(gShadowMem == this)
      << "Broken program invariant permitting at most one active instance "
      << "of shadow memory.";

  gShadowMem = nullptr;

  // Restore any previous handler for SIGSEGV.
  if (gPrevSignalHandler.sa_handler) {
    ::sigaction(SIGSEGV, &gPrevSignalHandler, nullptr);
    gPrevSignalHandler = {};
  }

  for (auto base : shadow_pages) {
    CHECK(0 < last_shadow_page_size);
    munmap(base, last_shadow_page_size);
  }
}

bool ShadowMemory::AddPageForAddress(uint64_t addr) {
  if (addr != last_shadow_address) {
    return false;
  }

  auto page_size = 1ULL << page_granularity;
  auto shadow_page_size = LeastCommonMultiple(
      ((page_size >> shadow_granularity) * last_shadow_elem_size_bits) / 8,
      4096);

  if (!last_shadow_page_size) {
    last_shadow_page_size = shadow_page_size;
  } else {
    CHECK(last_shadow_page_size == shadow_page_size);
  }

  auto page_offset = ((addr - shadow_base) / shadow_page_size) *
                     shadow_page_size;
  auto shadow_page = page_offset + shadow_base;
  CHECK(shadow_page <= addr && addr < (shadow_page + shadow_page_size));

  auto desired_base = reinterpret_cast<void *>(shadow_page);
  auto alloc_base = mmap(desired_base, shadow_page_size, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
  auto err = errno;
  CHECK(desired_base == alloc_base)
      << "Unable to allocate " << shadow_page_size << " bytes at "
      << desired_base << " (got " << alloc_base << ") for shadow memory: "
      << strerror(err);

  DLOG(INFO)
        << "Allocating " << shadow_page_size << " bytes at " << desired_base
        << " got it at " << alloc_base << " accessing " << std::hex
        << addr << std::dec;

  shadow_pages.push_back(alloc_base);
  return true;
}

}  // namespace vmill
