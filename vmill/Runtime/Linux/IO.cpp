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

namespace {

int DoRead(Memory *memory, int fd, addr_t buf, size_t size,
           size_t *out_num_bytes) {

  // TODO(pag): Not 100% right; can have partial reads at the page granularity.
  if (!CanWriteMemory(memory, buf, size)) {
    return EFAULT;
  }

  ssize_t read_bytes = 0;
  for (auto max_bytes = static_cast<ssize_t>(size); read_bytes < max_bytes; ) {
    auto remaining_bytes = max_bytes - read_bytes;
    auto wanted_bytes = std::min<ssize_t>(remaining_bytes, kIOBufferSize);
    errno = 0;
    auto num_bytes = read(fd, gIOBuffer, static_cast<size_t>(wanted_bytes));
    auto err = errno;
    if (0 >= num_bytes) {
      if (read_bytes || !errno) {
        break;
      } else {
        return err;
      }
    } else {
      memory = CopyToMemory(memory, buf, gIOBuffer,
                            static_cast<size_t>(num_bytes));
      buf += static_cast<size_t>(num_bytes);
      *out_num_bytes += static_cast<size_t>(num_bytes);
      read_bytes += num_bytes;
    }
  }

  return 0;
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
    STRACE_ERROR(read, "Error reading %d bytes from fd=%d: %s",
                 size, fd, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(read, "fd=%d, size=%d/%d", fd, num_read_bytes, size);
    return syscall.SetReturn(memory, state,
                             static_cast<addr_t>(num_read_bytes));
  }
}

static int DoWrite(Memory *memory, int fd, addr_t buf, size_t size,
                   size_t *num_written_bytes) {

  // TODO(pag): Not 100% right; can have partial reads at the page granularity.
  if (!CanReadMemory(memory, buf, size)) {
    return EFAULT;
  }

  ssize_t written_bytes = 0;
  for (auto max_bytes = static_cast<ssize_t>(size);
       written_bytes < max_bytes; ) {

    auto num_bytes_left = size - static_cast<size_t>(written_bytes);
    auto num_to_copy = std::min<size_t>(kIOBufferSize, num_bytes_left);
    CopyFromMemory(memory, gIOBuffer, buf, num_to_copy);

    errno = 0;
    auto num_bytes = write(fd, gIOBuffer, num_to_copy);
    auto err = errno;
    if (0 >= num_bytes) {
      if (written_bytes) {
        break;
      } else {
        return err;
      }
    } else {
      written_bytes += num_bytes;
      *num_written_bytes += static_cast<size_t>(num_bytes);
    }
  }
  return 0;
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
    STRACE_ERROR(write, "Error writing %d bytes to fd=%d: %s",
                 size, fd, strerror(err));
    return syscall.SetReturn(memory, state, -err);

  } else {
    STRACE_SUCCESS(write, "fd=%d, size=%d/%d", fd, num_written_bytes, size);
    return syscall.SetReturn(memory, state,
                             static_cast<addr_t>(num_written_bytes));
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
      STRACE_ERROR(readv, "Couldn't read %u vector element", i);
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    auto err = DoRead(memory, fd, vec.iov_base, vec.iov_len, &num_read_bytes);
    if (err) {
      STRACE_ERROR(readv, "Couldn't read data into %u vector element", i);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(readv, "fd=%d, iovcount=%u, size=%d", fd, iovcount,
                 num_read_bytes);
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
      STRACE_ERROR(writev, "Couldn't read %u vector element", i);
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    auto err = DoWrite(memory, fd, vec.iov_base, vec.iov_len,
                       &num_written_bytes);
    if (err) {
      STRACE_ERROR(writev, "Couldn't write data from %u vector element", i);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(writev, "fd=%d, iovcount=%u, size=%d", fd, iovcount,
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
                   gPath, oflag, mode, fd);
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

  errno = 0;
  auto ret = close(fd);
  if (errno) {
    STRACE_ERROR(close, "Error closing fd %d: %s", fd, strerror(errno));
  } else {
    STRACE_SUCCESS(close, "fd=%d, ret=%d", fd, ret);
  }
  return syscall.SetReturn(memory, state, ret * errno);
}

// Emulate a `close` system call.
static Memory *SysIoctl(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  int fd = -1;
  unsigned long request = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &request)) {
    STRACE_ERROR(ioctl, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  switch (request) {
    case TCGETS:
      STRACE_ERROR(ioctl_tcgets, "No tty.");
      return syscall.SetReturn(memory, state, -ENOTTY);
    case TCSETS:
      STRACE_ERROR(ioctl_tcsets, "No tty.");
      return syscall.SetReturn(memory, state, -ENOTTY);
    case TIOCGWINSZ:
      STRACE_ERROR(ioctl_tiocgwinsz, "No tty.");
      return syscall.SetReturn(memory, state, -ENOTTY);
    default:
      return syscall.SetReturn(memory, state, -EINVAL);
  }
}

}  // namespace
