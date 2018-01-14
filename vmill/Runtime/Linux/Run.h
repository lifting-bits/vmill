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
#ifndef TOOLS_VMILL_VMILL_RUNTIME_LINUX_RUN_H_
#define TOOLS_VMILL_VMILL_RUNTIME_LINUX_RUN_H_

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif  // _GNU_SOURCE

#ifndef __USE_POSIX
# define __USE_POSIX
#endif  // __USE_POSIX

#ifndef __USE_ATFILE
# define __USE_ATFILE
#endif

#include <algorithm>
#include <csignal>
#include <ctime>
#include <linux/limits.h>
#include <linux/net.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/vfs.h>  // Maybe `sys/statfs.h` on other systems.
#include <unistd.h>

#ifndef ERESTARTSYS
# define ERESTARTSYS 512
#endif

#include "vmill/Runtime/Task.h"

#if 32 == ADDRESS_SIZE_BITS
# define PRIdADDR PRId32
# define PRIxADDR PRIx32
# define PRIuADDR PRIu32
#else
# define PRIdADDR PRId64
# define PRIxADDR PRIx64
# define PRIuADDR PRIu64
#endif

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif  // PATH_MAX

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 64
#endif  // HOST_NAME_MAX

namespace {

enum : size_t {
  kIOBufferSize = 4096UL * 4,
  kOldOldUTSNameLen = 8UL,
  kOldUTSNameLen = 64UL,
  kNewUTSNameLen = 64UL
};

struct linux_sockaddr : public sockaddr {
  char sa_data_extra[128 - sizeof(struct sockaddr)];  // Full Protocol address.
} __attribute__((packed));

struct linux32_iovec {
  addr32_t iov_base;
  uint32_t iov_len;
};

struct linux64_iovec {
  addr64_t iov_base;
  uint64_t iov_len;
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

struct linux64_msghdr {
  addr64_t msg_name;  // `void *`.
  uint32_t msg_namelen;
  addr64_t msg_iov;  // `struct linux32_iovec *`.
  uint32_t msg_iovlen;
  addr64_t msg_control;  // `void *`.
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

struct linux64_timespec {
  uint64_t tv_sec;
  uint64_t tv_nsec;
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

struct stat x;

struct linux64_stat {
  uint64_t st_dev;
  uint64_t st_ino;
  uint64_t st_nlink;
  uint32_t st_mode;
  uint32_t st_uid;
  uint32_t st_gid;
  uint32_t __pad0;
  uint64_t st_rdev;
  int64_t st_size;
  int64_t st_blksize;
  int64_t st_blocks;
  struct linux64_timespec st_atim;
  struct linux64_timespec st_mtim;
  struct linux64_timespec st_ctim;
  int64_t __glibc_reserved[3];
} __attribute__((packed));

static_assert(sizeof(linux64_stat) == 144,
              "Invalid packing of `struct linux64_stat`.");


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

struct linux_sysinfo {
  addr_diff_t uptime;
  addr_t loads[3];
  addr_t totalram;
  addr_t freeram;
  addr_t sharedram;
  addr_t bufferram;
  addr_t totalswap;
  addr_t freeswap;
  uint16_t procs;
  uint16_t pad;
  addr_t totalhigh;
  addr_t freehigh;
  uint32_t mem_unit;
};

struct linux_rlimit {
  addr_t rlim_cur;
  addr_t rlim_max;
};

struct linux_compat_rlimit {
  uint32_t rlim_cur;
  uint32_t rlim_max;
};

enum : size_t {
  kLinuxNumTerminalControlChars = 19
};

struct linux_termios {
  uint32_t c_iflag;  // Input mode flags.
  uint32_t c_oflag;  // Output mode flags.
  uint32_t c_cflag;  // Control mode flags.
  uint32_t c_lflag;  // Local mode flags.
  uint8_t c_line;  // Line discipline.
  uint8_t c_cc[kLinuxNumTerminalControlChars];  // Control characters.
};

enum : uint32_t {
  kLinuxMinIndexForTLSInGDT = 12,
  kLinuxMaxIndexForTLSInGDT = 14,
  kNumTLSSlots = (kLinuxMaxIndexForTLSInGDT - kLinuxMinIndexForTLSInGDT) + 1
};

enum SegContentType : uint32_t {
  kSegContentsData,
  kSegContentsDataExpandDown,
  kSegContentsNonConformingCode,
  kSegContentsConformingCode
};

struct linux_x86_user_desc {
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
} __attribute__((packed));

struct linux_iovec {
  addr_t iov_base;
  addr_t iov_len;
};

struct linux_dirent {
  addr_t d_ino;
  addr_t d_off;
  uint16_t d_reclen;
  // char d_name[];
} __attribute__((packed));

struct linux_dirent64 {
  uint64_t d_ino;
  uint64_t d_off;
  uint16_t d_reclen;
  uint8_t d_type;
  // char d_name[];
} __attribute__((packed));

struct linux32_statfs64 {
  uint32_t f_type;
  uint32_t f_bsize;
  uint64_t f_blocks;
  uint64_t f_bfree;
  uint64_t f_bavail;
  uint64_t f_files;
  uint64_t f_ffree;
  uint64_t f_fsid;
  uint32_t f_namelen;
  uint32_t f_frsize;
  uint32_t f_flags;
  uint32_t f_spare[4];
} __attribute__((packed));

// NOTE(pag): We never want to have a zero TID, because otherwise we'll get
//            into funky issues where `pthread_rwlock_wrlock` writes the TID
//            into `rwlock->__data.__writer`, and then, if this value is zero
//            (and another condition is met), the `pthread_rwlock_unlock` code
//            will execute an `XEND` instruction (without the accompanying
//            `XBEGIN`), resulting in a `__remill_error` being executed.
constexpr pid_t kParentProcessId = 1;
static constexpr pid_t kProcessId = 2;
static constexpr pid_t kParentProcessGroupId = 0;

// Number of iterations of the task loop to be blocked for.
static constexpr unsigned kFutexBlockedForABit = 100;

// Basically infinity.
static constexpr unsigned kBlockedForever = ~0U;

// State needed to emulate a Linux thread.
struct linux_task : public vmill::Task {
 public:
  linux_task *next;
  linux_task *next_circular;
  linux_x86_user_desc tls_slots[kNumTLSSlots];

  // Used for scheduling, e.g. `sleep`, `futex`, etc.
  unsigned blocked_count;
  unsigned wake_count;

  // Information about an active futex. This is mostly specific to tasks
  // that are blocked on futexes.
  uint32_t futex_bitset;
  addr_t futex_uaddr;

  pid_t tid;
  addr_t clear_child_tid;
  addr_t set_child_tid;
};

// Returns a pointer to the currently executing task.
extern "C" linux_task *__vmill_current(void);

// Add a task to the operating system.
extern "C" linux_task *__vmill_create_task(
    const void *state, vmill::PC pc, vmill::AddressSpace *memory);

}  // namespace

#endif  // TOOLS_VMILL_VMILL_RUNTIME_LINUX_RUN_H_
