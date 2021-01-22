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
#include <new>
#include <random>

namespace {

static constexpr uint64_t kPageSize = 4096;
static constexpr uint64_t kMmapMinAddr = 65536;
static constexpr uint64_t k1GiB = 1ULL << 30ULL;
static constexpr uint64_t k4GiB = k1GiB * 4ULL;

// Minimum allowed address for an `mmap`. On 64-bit, this is any address
// above the 4 GiB. In 32-bit, this is anything above 1 GiB.
static constexpr addr_t kAllocMin = IF_64BIT_ELSE(k4GiB, k1GiB);

// Maximum allowed address for an `mmap`.
static constexpr addr_t kAllocMax = IF_64BIT_ELSE((1ULL << 47ULL),
                                                  0xf7000000);
// Emulate an `brk` system call.
static Memory *SysBrk(Memory *memory, State *state,
                      const SystemCallABI &syscall) {
  addr_t addr = 0;
  if (!syscall.TryGetArgs(memory, state, &addr)) {
    STRACE_ERROR(brk, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  // Special case -- if address is `0` just return current pointer
  auto current = __vmill_current()->program_break;
  if (addr == 0) {
    STRACE_SUCCESS(brk, "addr=%" PRIxADDR " -> %x" PRIxADDR, 0, current);
    return syscall.SetReturn(memory, state, current);
  }

  // TODO(lukas): This means the `program_break` was this task was not set
  //              and we do not yet resolve this (we would like though)
  if (current == 0) {
    STRACE_ERROR(brk, " program break is 0");
    return syscall.SetReturn(memory, state, current);
  }

  auto size = addr - current;
  memory = __vmill_allocate_memory(memory, current, size, "[heap] after brk", 0);
  memory = __vmill_protect_memory(memory, current, size, true, true, false);
  auto ret = current + size;
  __vmill_current()->program_break = ret;

  STRACE_SUCCESS(brk, "addr=%" PRIxADDR " -> %x" PRIxADDR, current, ret);
  return syscall.SetReturn(memory, state, ret);
}

#ifndef MAP_GROWSDOWN
# define MAP_GROWSDOWN 0x00100
#endif

#ifndef MAP_GROWSUP
# define MAP_GROWSUP 0
#endif

#ifndef MAP_STACK
# define MAP_STACK 0x20000
#endif

// Emulate an `mmap` system call.
static Memory *SysMmap(Memory *memory, State *state,
                       const SystemCallABI &syscall,
                       addr_t offset_scale=1) {
  addr_t addr = 0;
  addr_t size = 0;
  int prot = 0;
  int flags = 0;
  int fd = -1;
  off_t offset = 0;
  if (!syscall.TryGetArgs(memory, state, &addr, &size, &prot, &flags,
                          &fd, &offset)) {
    STRACE_ERROR(mmap, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto input_addr = addr;
  offset *= offset_scale;

  size = AlignToNextPage(size);
  if (!size) {  // Size not page aligned.
    STRACE_ERROR(mmap, "Zero-sized allocation");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // TODO(pag): Not quite right, we have limited support for file-backed memory
  //            mappings.
  if (-1 != fd) {
    if (STDIN_FILENO == fd || STDOUT_FILENO == fd || STDERR_FILENO == fd) {
      STRACE_ERROR(mmap, "Using I/O fd %d", fd);
      return syscall.SetReturn(memory, state, -EACCES);

    } else if (-1 > fd) {
      STRACE_ERROR(mmap, "Invalid fd %d", fd);
      return syscall.SetReturn(memory, state, -EBADFD);

    } else if (0 > offset || offset % 4096) {  // Not page-aligned.
      STRACE_ERROR(mmap, "Unaligned offset %" PRId64 " of fd %d", offset, fd);
      return syscall.SetReturn(memory, state, -EINVAL);
    }

    if (offset > (offset + static_cast<ssize_t>(size))) {  // Signed overflow.
      STRACE_ERROR(mmap, "Signed overflow of offset %" PRId64 " and size %"
                   PRIxADDR " for fd %d", offset, size, fd);
      return syscall.SetReturn(memory, state, -EOVERFLOW);
    }
  }

  auto max_addr = kAllocMax;
#if 64 == ADDRESS_SIZE_BITS
# ifndef MAP_32BIT
#   define MAP_32BIT 0x40
# endif
  if (0 != (MAP_32BIT & flags)) {
    max_addr = k4GiB;
    if (addr && addr >= max_addr) {
      addr = 0;
    }
  }
#endif

  // Unsupported flags.
  if ((MAP_GROWSDOWN & flags)) {
    STRACE_ERROR(mmap, "Unsupported flag: MAP_GROWSDOWN");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // Unsupported flags.
  if ((MAP_GROWSUP & flags)) {
    STRACE_ERROR(mmap, "Unsupported flag: MAP_GROWSUP");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // TODO(pag): Handle this at the VMill level?
  if ((MAP_SHARED & flags)) {
    flags &= ~MAP_SHARED;
    flags |= MAP_PRIVATE;
  }

  // Required flags.
  if (!(MAP_PRIVATE & flags)) {
    STRACE_ERROR(mmap, "Not a private mmap");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // A mapping can't be both anonymous and file-backed.
  if (0 <= fd && (MAP_ANONYMOUS & flags)) {
    STRACE_ERROR(mmap, "Must be file-backed or anonymous, but not both");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // Check the hinted address.
  if (MAP_FIXED & flags) {
    addr = AlignToPage(addr);
    if (!addr) {
      STRACE_ERROR(mmap, "Can't allocate the null page");
      return syscall.SetReturn(memory, state, -EINVAL);

    // TODO(pag): Figure out what the correct behavior is here.
    } else if (addr < kMmapMinAddr) {
      addr = kMmapMinAddr;  // Silently round it up to the minimum.
    }

    if ((addr + size) > max_addr) {
      STRACE_ERROR(mmap, "Fixed addr=%" PRIxADDR "+size=%" PRIxADDR " too big",
                   addr, size);
      return syscall.SetReturn(memory, state, -ENOMEM);
    }
  } else {
    addr = 0;  // TODO(pag): Is it right to not check this?
  }

  // Try to go and find a region of memory to map, assuming that one has
  // not been explicitly requested.
  if (!addr) {
    addr = __vmill_find_unmapped_address(memory, kMmapMinAddr, max_addr, size);
    if (!addr) {
      STRACE_ERROR(mmap, "Out of memory for request of size %" PRIxADDR, size);
      return syscall.SetReturn(memory, state, -ENOMEM);
    }
  }

  // Try to emulate file-backed `mmap`s by reading in the contents from disk.
  //
  // TODO(pag): In the future we could probably handle shared mappings by
  //            stealing a new fd (with `dup`), and recording some meta-data
  //            to note when to flush the mapped data.
  off_t old_offset = 0;
  const char *fd_name = nullptr;
  uint64_t fd_offset = 0;

  if (0 <= fd) {
    old_offset = lseek(fd, 0, SEEK_CUR);

    if (-1 == old_offset) {
      auto err = errno;
      STRACE_ERROR(mmap, "Couldn't get old seek position for fd %d: %s",
                   fd, strerror(err));
      return syscall.SetReturn(memory, state, -err);
    }

    // TODO(pag): Issue #11: is `offset` relative to the start of the file,
    //            or is is relative to `old_offset`?

    // Seek to the end of the range where we want to `mmap`. This is a dumb
    // way of checking to see that the region of memory is big enough to be
    // `mmap`ed.
    if (-1 == lseek(fd, offset + static_cast<off_t>(size), SEEK_SET)) {
      auto err = errno;
      STRACE_ERROR(mmap, "Couldn't get set seek position for fd %d: %s",
                   fd, strerror(err));
      memory = syscall.SetReturn(memory, state, -err);
    }

    if (-1 == lseek(fd, offset, SEEK_SET)) {
      auto err = errno;
      STRACE_ERROR(mmap, "Couldn't set new seek position for fd %d: %s",
                   fd, strerror(err));
      memory = syscall.SetReturn(memory, state, -err);
      lseek(fd, old_offset, SEEK_SET);  // Maintain transparency.
      return memory;
    }

    fd_name = GetBasePathAt(fd);
    fd_offset = static_cast<uint64_t>(offset);
  }

  if (!fd_name && 0 != (MAP_STACK & flags)) {
    fd_name = "[stack]";
  }

  // Allocate the RW memory.
  memory = __vmill_allocate_memory(memory, addr, size, fd_name, fd_offset);

  // Copy data from the file into the memory mapping.
  if (0 <= fd) {
    addr_t remaining = size;
    for (addr_t i = 0; remaining; ) {
      auto ret = read(fd, gIOBuffer,
                      std::min<addr_t>(remaining, kIOBufferSize));

      // Failed to copy part of the file into memory, need to reset the seek
      // head to its prior value to maintain transparency, then free the just
      // allocated memory.
      if (-1 == ret) {
        auto err = errno;
        STRACE_ERROR(mmap, "Couldn't copy bytes from backing fd %d: %s",
                     fd, strerror(err));

        memory = syscall.SetReturn(memory, state, -err);
        lseek(fd, old_offset, SEEK_SET);  // Reset.
        return __vmill_free_memory(memory, addr, size);

      } else if (ret) {
        auto num_copied_bytes = static_cast<addr_t>(ret);
        memory = CopyToMemory(memory, addr + i, gIOBuffer, num_copied_bytes);
        remaining -= num_copied_bytes;
        i += num_copied_bytes;

      // Probably the size of the MMAP is rounded up to be larger than the
      // size of what (remains) in the file.
      } else {
        break;
      }
    }

    lseek(fd, old_offset, SEEK_SET);  // Reset.
  }

  bool can_read = PROT_READ & prot;
  bool can_write = PROT_WRITE & prot;
  bool can_exec = PROT_EXEC & prot;

  // Change the memory permissions if they are not the default ones.
  if (can_exec || !can_read || !can_write) {
    memory = __vmill_protect_memory(memory, addr, size, can_read,
                                    can_write, can_exec);
  }

  STRACE_SUCCESS(
      mmap, "addr=%" PRIxADDR ", size=%" PRIxADDR ", read=%d, "
            "write=%d, exec=%d, fd=%d, offset=%" PRId64 ", return=%" PRIxADDR,
      input_addr, size, can_read, can_write, can_exec, fd, offset, addr);

  return syscall.SetReturn(memory, state, addr);
}

// Emulate an `munmap` system call.
static Memory *SysMunmap(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  addr_t addr = 0;
  addr_t size = 0;
  if (!syscall.TryGetArgs(memory, state, &addr, &size)) {
    STRACE_ERROR(munmap, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);

  } else if (addr != AlignToPage(addr)) {
    STRACE_ERROR(munmap, "Unaligned address %" PRIxADDR, addr);
    return syscall.SetReturn(memory, state, -EINVAL);

  }

  size = AlignToNextPage(size);
  if (!size) {
    STRACE_ERROR(munmap, "Zero-sized munmap");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  STRACE_SUCCESS(munmap, "addr=%" PRIxADDR ", size=%" PRIxADDR, addr, size);
  memory = __vmill_free_memory(memory, addr, size);
  return syscall.SetReturn(memory, state, 0);
}


// Emulate an `mprotect` system call.
static Memory *SysMprotect(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  addr_t addr = 0;
  addr_t size = 0;
  int prot = 0;
  if (!syscall.TryGetArgs(memory, state, &addr, &size, &prot)) {
    STRACE_ERROR(mprotect, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  size = AlignToNextPage(size);
  if (!size) {
    STRACE_ERROR(mprotect, "Zero-sized munmap");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  bool can_read = PROT_READ & prot;
  bool can_write = PROT_WRITE & prot;
  bool can_exec = PROT_EXEC & prot;

  STRACE_SUCCESS(
      mprotect, "addr=%" PRIxADDR ", size=%" PRIxADDR
      ", read=%d, write=%d, exec=%d", addr, size, can_read,
      can_write, can_exec);

  memory = __vmill_protect_memory(memory, addr, size, can_read,
                                  can_write, can_exec);

  return syscall.SetReturn(memory, state, 0);
}

}  // namespace
