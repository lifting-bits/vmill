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

#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <poll.h>

namespace {

static int DoRead(Memory *memory, int fd, addr_t buf, size_t size,
                  size_t *out_num_bytes) {

  // TODO(pag): Not 100% right; can have partial reads at the page granularity.
  if (!CanWriteMemory(memory, buf, size)) {
    return EFAULT;
  }

  auto bytes_read = new uint8_t[size];
  auto num_bytes = read(fd, bytes_read, size);
  auto err = errno;
  if (-1 != num_bytes) {
    err = 0;
    *out_num_bytes += static_cast<size_t>(num_bytes);
    memory = CopyToMemory(memory, buf, bytes_read,
                          static_cast<size_t>(num_bytes));
  }

  delete[] bytes_read;
  return err;
}

// Emulate a `read` system call.
static Memory *SysRead(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  addr_t size = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &size)) {
    STRACE_ERROR(read, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  size_t num_read_bytes = 0;
  auto err = DoRead(memory, fd, buf, size, &num_read_bytes);
  if (err) {
    STRACE_ERROR(read, "Error reading %" PRIuADDR " bytes from fd=%d: %s",
                 size, fd, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(read, "fd=%d, size=%zu/%" PRIuADDR,
                   fd, num_read_bytes, size);
    return syscall.SetReturn(
        memory, state, static_cast<addr_t>(num_read_bytes));
  }
}

static int DoWrite(Memory *memory, int fd, addr_t buf, size_t size,
                   size_t *num_written_bytes) {

  // TODO(pag): Not 100% right; can have partial reads at the page granularity.
  if (!CanReadMemory(memory, buf, size)) {
    return EFAULT;
  }

  auto write_bytes = new uint8_t[size];
  CopyFromMemory(memory, write_bytes, buf, size);
  auto num_bytes = write(fd, write_bytes, size);
  auto err = errno;
  delete[] write_bytes;

  if (-1 != num_bytes) {
    err = 0;
    *num_written_bytes += static_cast<size_t>(num_bytes);
  }

  return err;
}

// Emulate a `read` system call.
static Memory *SysWrite(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  addr_t size = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &size)) {
    STRACE_ERROR(write, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  size_t num_written_bytes = 0;
  auto err = DoWrite(memory, fd, buf, size, &num_written_bytes);
  if (err) {
    STRACE_ERROR(write, "Error writing %" PRIuADDR " bytes to fd=%d: %s",
                 size, fd, strerror(err));
    return syscall.SetReturn(memory, state, -err);

  } else {
    STRACE_SUCCESS(write, "fd=%d, size=%zu/%" PRIuADDR,
                   fd, num_written_bytes, size);
    return syscall.SetReturn(
        memory, state, static_cast<addr_t>(num_written_bytes));
  }
}

// Emulate a `readv` system call.
static Memory *SysReadV(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t iov = 0;
  addr_t iovcount = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &iov, &iovcount)) {
    STRACE_ERROR(readv, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  size_t num_read_bytes = 0;

  for (addr_t i = 0; i < iovcount; ++i) {
    linux_iovec vec = {};
    if (!TryReadMemory(memory, iov + sizeof(vec) * i, &vec)) {
      STRACE_ERROR(readv, "Couldn't read %" PRIuADDR " vector element", i);
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    auto err = DoRead(memory, fd, vec.iov_base, vec.iov_len, &num_read_bytes);
    if (err) {
      STRACE_ERROR(
          readv, "Couldn't read data into %" PRIuADDR " vector element", i);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(readv, "fd=%d, iovcount=%" PRIuADDR ", size=%zu",
                 fd, iovcount, num_read_bytes);
  return syscall.SetReturn(
      memory, state, static_cast<addr_t>(num_read_bytes));
}

// Emulate a `writev` system call.
static Memory *SysWriteV(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t iov = 0;
  addr_t iovcount = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &iov, &iovcount)) {
    STRACE_ERROR(writev, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  size_t num_written_bytes = 0;

  for (addr_t i = 0; i < iovcount; ++i) {
    linux_iovec vec = {};
    if (!TryReadMemory(memory, iov + sizeof(vec) * i, &vec)) {
      STRACE_ERROR(writev, "Couldn't read %" PRIuADDR " vector element", i);
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    auto err = DoWrite(memory, fd, vec.iov_base, vec.iov_len,
                       &num_written_bytes);
    if (err) {
      STRACE_ERROR(
          writev, "Couldn't write data from %" PRIuADDR " vector element", i);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(
      writev, "fd=%d, iovcount=%" PRIuADDR ", size=%zu", fd, iovcount,
      num_written_bytes);

  return syscall.SetReturn(
      memory, state, static_cast<addr_t>(num_written_bytes));
}

// Emulate an `open` system call.
static Memory *SysOpen(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  addr_t path = 0;
  int oflag = 0;
  mode_t mode = 0;
  if (!syscall.TryGetArgs(memory, state, &path, &oflag, &mode)) {
    STRACE_ERROR(open, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';

  if (path_len >= PATH_MAX) {
    STRACE_ERROR(open, "Path name too long: %s", gPath);
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);

  // The string read does not end in a NUL-terminator; i.e. we read less
  // than `PATH_MAX`, but as much as we could without faulting, and we didn't
  // read the NUL char.
  } else if ('\0' != gPath[path_len]) {
    STRACE_ERROR(open, "Non-NUL-terminated path");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto fd = open(gPath, oflag, mode);

  if (-1 == fd) {
    auto err = errno;
    STRACE_ERROR(open, "Couldn't open %s: %s", gPath, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(open, "path=%s, flags=%x, mode=%o, fd=%d",
                   gPath, oflag, mode, fd);
    return syscall.SetReturn(memory, state, fd);
  }
}

// Emulate an `openat` system call.
static Memory *SysOpenAt(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int dirfd = -1;
  addr_t path = 0;
  int oflag = 0;
  mode_t mode = 0;
  if (!syscall.TryGetArgs(memory, state, &dirfd, &path, &oflag, &mode)) {
    STRACE_ERROR(openat, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';

  if (path_len >= PATH_MAX) {
    STRACE_ERROR(openat, "Path name too long: %s", gPath);
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);

  // The string read does not end in a NUL-terminator; i.e. we read less
  // than `PATH_MAX`, but as much as we could without faulting, and we didn't
  // read the NUL char.
  } else if ('\0' != gPath[path_len]) {
    STRACE_ERROR(openat, "Non-NUL-terminated path");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto fd = openat(dirfd, gPath, oflag, mode);

  if (-1 == fd) {
    auto err = errno;
    STRACE_ERROR(openat, "Couldn't open %s: %s", gPath, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(openat, "dirfd=%d, path=%s, flags=%x, mode=%o, fd=%d",
                   dirfd, gPath, oflag, mode, fd);
    return syscall.SetReturn(memory, state, fd);
  }
}

// Emulate a `close` system call.
static Memory *SysClose(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  int fd = -1;
  if (!syscall.TryGetArgs(memory, state, &fd)) {
    STRACE_ERROR(close, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto ret = close(fd);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(close, "Error closing fd %d: %s", fd, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  STRACE_SUCCESS(close, "fd=%d", fd);
  return syscall.SetReturn(memory, state, 0);
}

// Emulate an `ioctl` system call.
static Memory *SysIoctl(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  int fd = -1;
  unsigned long cmd = 0;
  addr_t argp = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &cmd, &argp)) {
    STRACE_ERROR(ioctl, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (0 > fd) {
    STRACE_ERROR(ioctl, "Bad file descriptor fd=%d", fd);
    return syscall.SetReturn(memory, state, -EBADF);
  }

  struct termios info = {};

  switch (cmd) {
    case TCGETS:
      if (!ioctl(fd, TCGETS, &info)) {
        if (!TryWriteMemory(memory, argp, info)) {
          STRACE_ERROR(ioctl_tcgets, "Fault writing info fd=%d argp=%" PRIxADDR,
                       fd, argp);
          return syscall.SetReturn(memory, state, -EFAULT);
        } else {
          STRACE_SUCCESS(ioctl_tcgets, "fd=%d", fd);
          return syscall.SetReturn(memory, state, 0);
        }
      } else {
        auto err = errno;
        STRACE_ERROR(ioctl_tcgets, "Error with fd=%d: %s", fd, strerror(err));
        return syscall.SetReturn(memory, state, -err);
      }

    case TCSETS:
      if (TryReadMemory(memory, argp, &info)) {
        if (!ioctl(fd, TCSETS, &info)) {
          STRACE_SUCCESS(ioctl_tcsets, "fd=%d", fd);
          return syscall.SetReturn(memory, state, 0);
        } else {
          auto err = errno;
          STRACE_ERROR(ioctl_tcsets, "Error with fd=%d: %s", fd, strerror(err));
          return syscall.SetReturn(memory, state, -err);
        }
      } else {
        STRACE_ERROR(ioctl_tcsets, "Fault reading info fd=%d argp=%" PRIxADDR,
                     fd, argp);
        return syscall.SetReturn(memory, state, -EFAULT);
      }

    case TIOCGWINSZ:
      STRACE_ERROR(ioctl_tiocgwinsz, "No tty.");
      return syscall.SetReturn(memory, state, -ENOTTY);

    default:
      STRACE_ERROR(ioctl, "Unsupported cmd=%lu on fd=%d", cmd, fd);
      return syscall.SetReturn(memory, state, 0);
  }
}

// Emulate a `poll` system call.
static Memory *SysPoll(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  addr_t fds = 0;
  uint32_t nfds = 0;
  int timeout_msec = 0;
  if (!syscall.TryGetArgs(memory, state, &fds, &nfds, &timeout_msec)) {
    STRACE_ERROR(poll, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct rlimit lim = {};
  getrlimit(RLIMIT_NOFILE, &lim);
  auto max_fds = std::min(lim.rlim_cur, lim.rlim_max);
  if (nfds >= max_fds) {
    STRACE_ERROR(poll, "nfds=%u is too big (max %lu)", nfds, max_fds);
    return syscall.SetReturn(memory, state, -ENOMEM);
  }

  auto fd_mem_size = nfds * sizeof(struct pollfd);
  if (!CanReadMemory(memory, fds, fd_mem_size)) {
    STRACE_ERROR(
        poll, "Can't read all bytes=%lu pointed to by fds=%" PRIxADDR,
        fd_mem_size, fds);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto poll_fds = new pollfd[nfds];
  CopyFromMemory(memory, poll_fds, fds, fd_mem_size);

  auto ret = poll(poll_fds, nfds, timeout_msec);
  auto err = errno;

  if (-1 == ret) {
    delete[] poll_fds;
    STRACE_ERROR(
        poll, "Error polling nfds=%u fds=%" PRIxADDR ": %s",
        nfds, fds, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  if (!CanWriteMemory(memory, fds, fd_mem_size)) {
    delete[] poll_fds;
    STRACE_ERROR(
        poll, "Can't write all bytes=%lu pointed to by fds=%" PRIxADDR,
        fd_mem_size, fds);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  CopyToMemory(memory, fds, poll_fds, fd_mem_size);
  delete[] poll_fds;

  STRACE_SUCCESS(poll, "fds=%" PRIxADDR ", nfds=%u, timeout=%d, ret=%d",
                 fds, nfds, timeout_msec, ret);
  return syscall.SetReturn(memory, state, ret);
}

}  // namespace
