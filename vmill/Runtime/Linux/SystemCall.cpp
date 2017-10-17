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

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif  // _GNU_SOURCE

#ifndef __USE_POSIX
# define __USE_POSIX
#endif  // __USE_POSIX

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <climits>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <linux/futex.h>
#include <linux/limits.h>
#include <linux/net.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <unistd.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#if 32 == ADDRESS_SIZE_BITS
# define PRIdADDR PRId32
# define PRIxADDR PRIx32
#else
# define PRIdADDR PRId64
# define PRIxADDR PRIx64
#endif

#if 1
# define STRACE_SYSCALL_NUM(nr) \
    fprintf(stderr, ANSI_COLOR_YELLOW "%u:" ANSI_COLOR_RESET, nr)

# define STRACE_ERROR(syscall, fmt, ...) \
    fprintf(stderr, ANSI_COLOR_RED #syscall ":" fmt ANSI_COLOR_RESET "\n", \
            ##__VA_ARGS__)

# define STRACE_SUCCESS(syscall, fmt, ...) \
    fprintf(stderr, ANSI_COLOR_GREEN #syscall ":" fmt ANSI_COLOR_RESET "\n", \
          ##__VA_ARGS__)
#else
# define STRACE_SYSCALL_NUM(...)
# define STRACE_ERROR(...)
# define STRACE_SUCCESS(...)
#endif

namespace {

enum : size_t {
  kIOBufferSize = 4096UL,
  kOldOldUTSNameLen = 8UL,
  kOldUTSNameLen = 64UL,
  kNewUTSNameLen = 64UL
};

// Intermediate buffer for copying data to/from the runtime memory and the
// emulated process memory.
static uint8_t gIOBuffer[kIOBufferSize] = {};

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif  // PATH_MAX

// Intermediate buffer for holding file system paths, used in various syscalls.
static char gPath[PATH_MAX + 1] = {};

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 64
#endif  // HOST_NAME_MAX

// Intermediate buffer for holding host names.
static char gHostName[HOST_NAME_MAX + 1] = {};

struct linux32_iovec {
  addr32_t iov_base;
  uint32_t iov_len;
};

struct linux32_msghdr {
  addr32_t msg_name;  // `void *`.
  uint32_t msg_namelen;
  addr32_t msg_iov;  // `struct linux32_iovec *`.
  uint32_t msg_iovlen;
  addr32_t msg_control;  // `void *`.
  uint32_t msg_controllen;
  int32_t msg_flags;
};

struct linux32_mmsghdr {
  linux32_msghdr msg_hdr;
  uint32_t msg_len;
};

struct linux32_cmsghdr {
  uint32_t cmsg_len;
  int32_t cmsg_level;
  int32_t cmsg_type;
};

struct linux64_msghdr {
  addr64_t msg_name;  // `void *`.
  uint32_t msg_namelen;
  addr64_t msg_iov;
  uint64_t msg_iovlen;
  addr64_t msg_control;
  uint64_t msg_controllen;
  int32_t msg_flags;
};

struct linux64_mmsghdr {
  linux64_msghdr msg_hdr;
  uint32_t msg_len;
};

struct linux64_cmsghdr {
  uint64_t cmsg_len;
  int32_t cmsg_level;
  int32_t cmsg_type;
};

struct linux32_timespec {
  uint32_t tv_sec;
  uint32_t tv_nsec;
};

struct linux32_timeval {
  uint32_t tv_sec;
  uint32_t tv_usec;
};

struct linux32_timezone {
  int32_t tz_minuteswest;
  int32_t tz_dsttime;
};

struct linux32_stat {
  uint64_t st_dev;
  uint16_t __pad1;
  uint32_t st_mode;
  uint32_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint64_t st_rdev;
  uint16_t __pad2;
  int64_t st_size;
  int32_t st_blksize;
  int64_t st_blocks;
  struct linux32_timespec st_atim;
  struct linux32_timespec st_mtim;
  struct linux32_timespec st_ctim;
  uint64_t st_ino;
} __attribute__((packed));

static_assert(sizeof(linux32_stat) == 88,
              "Invalid packing of `struct linux32_stat`.");

struct linux32_stat64 {
  uint64_t st_dev;
  uint32_t __pad1;
  uint32_t __st_ino;
  uint32_t st_mode;
  uint32_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint64_t st_rdev;
  uint32_t __pad2;
  int64_t st_size;
  int32_t st_blksize;
  int64_t st_blocks;
  struct linux32_timespec st_atim;
  struct linux32_timespec st_mtim;
  struct linux32_timespec st_ctim;
  uint64_t st_ino;
} __attribute__((packed));

static_assert(sizeof(linux32_stat64) == 96,
              "Invalid packing of `struct linux32_stat64`.");

struct linux_oldold_utsname {
  char sysname[kOldOldUTSNameLen + 1];
  char nodename[kOldOldUTSNameLen + 1];
  char release[kOldOldUTSNameLen + 1];
  char version[kOldOldUTSNameLen + 1];
  char machine[kOldOldUTSNameLen + 1];
};

struct linux_old_utsname {
  char sysname[kOldUTSNameLen + 1];
  char nodename[kOldUTSNameLen + 1];
  char release[kOldUTSNameLen + 1];
  char version[kOldUTSNameLen + 1];
  char machine[kOldUTSNameLen + 1];
};

struct linux_new_utsname {
  char sysname[kNewUTSNameLen + 1];
  char nodename[kNewUTSNameLen + 1];
  char release[kNewUTSNameLen + 1];
  char version[kNewUTSNameLen + 1];
  char machine[kNewUTSNameLen + 1];
  char domainname[kNewUTSNameLen + 1];
};

struct linux_rlimit {
  addr_t rlim_cur;
  addr_t rlim_max;
};

struct linux_compat_rlimit {
  uint32_t rlim_cur;
  uint32_t rlim_max;
};

enum SegContentType : uint32_t {
  kSegContentsData,
  kSegContentsDataExpandDown,
  kSegContentsNonConformingCode,
  kSegContentsConformingCode
};

struct linux_X86_user_desc {
  uint32_t entry_number;
  uint32_t base_addr;
  uint32_t limit;
  bool seg_32bit:1;
  SegContentType contents:2;
  bool read_exec_only:1;
  bool limit_in_pages:1;
  bool seg_not_present:1;
  bool useable:1;
#if defined(VMILL_RUNTIME_X86) && VMILL_RUNTIME_X86 == 64
  uint64_t lm:1;
  uint64_t _padding:24;
#else
  uint64_t _padding:25;
#endif

  // NOTE(pag): This intentially ignores `lm` because 32-bit code does not
  //            use that.
  bool IsEmpty(void) const {
    return !base_addr && !limit && !contents && read_exec_only &&
           !seg_32bit && !limit_in_pages && seg_not_present && !useable;
  }

  bool IsZero(void) const {
    return !base_addr && !limit && !contents && !read_exec_only &&
           !seg_32bit && !limit_in_pages && !seg_not_present && !useable;

  }
};

struct linux_iovec {
  addr_t iov_base;
  addr_t iov_len;
};
}  // namespace

#include "vmill/Runtime/Linux/Clock.cpp"
#include "vmill/Runtime/Linux/FS.cpp"
#include "vmill/Runtime/Linux/Futex.cpp"
#include "vmill/Runtime/Linux/IO.cpp"
#include "vmill/Runtime/Linux/MM.cpp"
#include "vmill/Runtime/Linux/Net.cpp"
#include "vmill/Runtime/Linux/Process.cpp"
#include "vmill/Runtime/Linux/Sys.cpp"
#include "vmill/Runtime/Linux/Thread.cpp"

namespace {

#ifdef VMILL_RUNTIME_X86

// 32-bit system call dispatcher for `int 0x80` and `sysenter` system call
// entry points.
static Memory *X86SystemCall(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  auto syscall_num = syscall.GetSystemCallNum(memory, state);
  STRACE_SYSCALL_NUM(syscall_num);
  switch (syscall_num) {
    case 1: return SysExit(memory, state, syscall);
    case 3: return SysRead(memory, state, syscall);
    case 4: return SysWrite(memory, state, syscall);
    case 5: return SysOpen(memory, state, syscall);
    case 6: return SysClose(memory, state, syscall);
    case 20: return SysGetProcessId(memory, state, syscall);
    case 24: return SysGetUserId(memory, state, syscall);
    case 33: return SysAccess(memory, state, syscall);
    case 45: return SysBrk(memory, state, syscall);
    case 47: return SysGetGroupId(memory, state, syscall);
    case 49: return SysGetEffectiveUserId(memory, state, syscall);
    case 50: return SysGetEffectiveGroupId(memory, state, syscall);
    case 54: return SysIoctl(memory, state, syscall);
    case 59: return SysUname<linux_oldold_utsname>(memory, state, syscall);
    case 64: return SysGetParentProcessId(memory, state, syscall);
    case 65: return SysGetProcessGroupId(memory, state, syscall);
    case 74: return SysSetHostName(memory, state, syscall);
    case 76: return SysGetRlimit<linux_rlimit>(memory, state, syscall);
    case 78: return SysGetTimeOfDay32(memory, state, syscall);
    case 79: return SysSetTimeOfDay32(memory, state, syscall);
    case 85: return SysReadLink(memory, state, syscall);
    case 90: return SysMmap(memory, state, syscall);
    case 91: return SysMunmap(memory, state, syscall);
    case 102: return SysSocketCall<uint32_t>(memory, state, syscall);
    case 106: return SysStat<linux32_stat>(memory, state, syscall);
    case 107: return SysLstat<linux32_stat>(memory, state, syscall);
    case 108: return SysFstat<linux32_stat>(memory, state, syscall);
    case 109: return SysUname<linux_old_utsname>(memory, state, syscall);
    case 122: return SysUname<linux_new_utsname>(memory, state, syscall);
    case 125: return SysMprotect(memory, state, syscall);
    case 140: return SysLlseek(memory, state, syscall);
    case 145: return SysReadV(memory, state, syscall);
    case 146: return SysWriteV(memory, state, syscall);
    case 174:
      STRACE_ERROR(rt_sigaction, "Suppressed");
      return syscall.SetReturn(memory, state, 0);
    case 175:
      STRACE_ERROR(rt_sigprocmask, "Suppressed");
      return syscall.SetReturn(memory, state, 0);
    case 183: return SysGetCurrentWorkingDirectory(memory, state, syscall);
    case 191: return SysGetRlimit<linux_compat_rlimit>(memory, state, syscall);
    case 192: return SysMmap(memory, state, syscall, kPageSize);
    case 195: return SysStat<linux32_stat64>(memory, state, syscall);
    case 196: return SysLstat<linux32_stat64>(memory, state, syscall);
    case 197: return SysFstat<linux32_stat64>(memory, state, syscall);
    case 199: return SysGetUserId(memory, state, syscall);
    case 200: return SysGetGroupId(memory, state, syscall);
    case 201: return SysGetEffectiveUserId(memory, state, syscall);
    case 202: return SysGetEffectiveGroupId(memory, state, syscall);
    case 224: return SysGetThreadId(memory, state, syscall);
    case 240: return SysFutex<linux32_timespec>(memory, state, syscall);
    case 243: return SysSetThreadArea<linux_X86_user_desc>(
        memory, state, syscall);
    case 295: return SysOpenAt(memory, state, syscall);
    case 307: return SysFAccessAt(memory, state, syscall);
    default:
      STRACE_ERROR(unsupported, "nr=%d", syscall_num);
      return syscall.SetReturn(memory, state, 0);
  }
}

#endif  // VMILL_RUNTIME_X86

#ifdef VMILL_RUNTIME_AARCH64

// 64-bit system call dispatcher for `svc` system call entry points.
static Memory *AArch64SystemCall(Memory *memory, State *state,
                                 const SystemCallABI &syscall) {
  auto syscall_num = syscall.GetSystemCallNum(memory, state);
  STRACE_SYSCALL_NUM(syscall_num);
  switch (syscall_num) {
    case 93: return SysExit(memory, state, syscall);
    case 63: return SysRead(memory, state, syscall);
    case 64: return SysWrite(memory, state, syscall);
    case 56: return SysOpenAt(memory, state, syscall);
    case 57: return SysClose(memory, state, syscall);
    case 172: return SysGetProcessId(memory, state, syscall);
    case 174: return SysGetUserId(memory, state, syscall);
    case 48: return SysFAccessAt(memory, state, syscall);
    case 214: return SysBrk(memory, state, syscall);
    case 176: return SysGetGroupId(memory, state, syscall);
    case 175: return SysGetEffectiveUserId(memory, state, syscall);
    case 177: return SysGetEffectiveGroupId(memory, state, syscall);
    case 29: return SysIoctl(memory, state, syscall);
    case 160: return SysUname<linux_new_utsname>(memory, state, syscall);
    case 173: return SysGetParentProcessId(memory, state, syscall);
    case 155: return SysGetProcessGroupId(memory, state, syscall);
    case 161: return SysSetHostName(memory, state, syscall);
    case 163: return SysGetRlimit<linux_rlimit>(memory, state, syscall);
    case 78: return SysGetTimeOfDay(memory, state, syscall);
    case 79: return SysSetTimeOfDay32(memory, state, syscall);
    case 85: return SysReadLink(memory, state, syscall);
    case 90: return SysMmap(memory, state, syscall);
    case 91: return SysMunmap(memory, state, syscall);
    case 102: return SysSocketCall<uint32_t>(memory, state, syscall);
    case 106: return SysStat<linux32_stat>(memory, state, syscall);
    case 107: return SysLstat<linux32_stat>(memory, state, syscall);
    case 108: return SysFstat<linux32_stat>(memory, state, syscall);
    case 125: return SysMprotect(memory, state, syscall);
    case 140: return SysLlseek(memory, state, syscall);
    case 145: return SysReadV(memory, state, syscall);
    case 146: return SysWriteV(memory, state, syscall);
    case 174:
      STRACE_ERROR(rt_sigaction, "Suppressed");
      return syscall.SetReturn(memory, state, 0);
    case 175:
      STRACE_ERROR(rt_sigprocmask, "Suppressed");
      return syscall.SetReturn(memory, state, 0);
    case 183: return SysGetCurrentWorkingDirectory(memory, state, syscall);
    case 191: return SysGetRlimit<linux_compat_rlimit>(memory, state, syscall);
    case 192: return SysMmap(memory, state, syscall, kPageSize);
    case 195: return SysStat<linux32_stat64>(memory, state, syscall);
    case 196: return SysLstat<linux32_stat64>(memory, state, syscall);
    case 197: return SysFstat<linux32_stat64>(memory, state, syscall);
    case 199: return SysGetUserId(memory, state, syscall);
    case 200: return SysGetGroupId(memory, state, syscall);
    case 201: return SysGetEffectiveUserId(memory, state, syscall);
    case 202: return SysGetEffectiveGroupId(memory, state, syscall);
    case 224: return SysGetThreadId(memory, state, syscall);
    case 240: return SysFutex<linux32_timespec>(memory, state, syscall);
    case 243: return SysSetThreadArea<linux_X86_user_desc>(
        memory, state, syscall);
    default:
      STRACE_ERROR(unsupported, "nr=%d", syscall_num);
      return syscall.SetReturn(memory, state, 0);
  }
}

#endif  // VMILL_RUNTIME_AARCH64

}  // namespace
