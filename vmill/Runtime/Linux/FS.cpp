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

namespace {

// Emulate an `access` system call.
static Memory *SysAccess(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  addr_t path = 0;
  int type = 0;
  if (!syscall.TryGetArgs(memory, state, &path, &type)) {
    STRACE_ERROR(access, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';

  if (path_len >= PATH_MAX) {
    STRACE_ERROR(access, "Path name too long: %s", gPath);
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);

  // The string read does not end in a NUL-terminator; i.e. we read less
  // than `PATH_MAX`, but as much as we could without faulting, and we didn't
  // read the NUL char.
  } else if ('\0' != gPath[path_len]) {
    STRACE_ERROR(access, "Non-NUL-terminated path");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto ret = access(gPath, type);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(access, "Can't access %s: %s", gPath, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(access, "path=%s, type=%d, ret=%d", gPath, type, ret);
    return syscall.SetReturn(memory, state, ret);
  }
}

// Emulate an `faccessat` system call.
static Memory *SysFAccessAt(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  int dirfd = 0;
  addr_t path = 0;
  int mode = 0;
  int flags = 0;
  if (!syscall.TryGetArgs(memory, state, &dirfd, &path, &mode, &flags)) {
    STRACE_ERROR(faccessat, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';

  if (path_len >= PATH_MAX) {
    STRACE_ERROR(faccessat, "Path name too long: %s", gPath);
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);

  // The string read does not end in a NUL-terminator; i.e. we read less
  // than `PATH_MAX`, but as much as we could without faulting, and we didn't
  // read the NUL char.
  } else if ('\0' != gPath[path_len]) {
    STRACE_ERROR(faccessat, "Non-NUL-terminated path");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto ret = faccessat(dirfd, gPath, mode, flags);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(faccessat, "Can't access %s: %s", gPath, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(faccessat, "dirfd=%d, path=%s, mode=%o, flags=%x, ret=%d",
                   dirfd, gPath, mode, flags, ret);
    return syscall.SetReturn(memory, state, ret);
  }
}


// Emulate an `llseek` system call.
static Memory *SysLlseek(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t offset_high = 0;
  addr_t offset_low = 0;
  addr_t result_addr = 0;
  int whence = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &offset_high, &offset_low,
                          &result_addr, &whence)) {
    STRACE_ERROR(llseek, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  uint64_t offset = offset_high;
  offset <<= 32;
  offset |= offset_low;

  auto offset64 = static_cast<off64_t>(offset);
  auto new_offset64 = lseek64(fd, offset64, whence);
  if (static_cast<off64_t>(-1) == new_offset64) {
    auto err = errno;
    STRACE_ERROR(llseek, "fd=%d, offset=%ld, whence=%d: %s",
                 fd, offset64, whence, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  if (!TryWriteMemory(memory, result_addr, new_offset64)) {
    STRACE_ERROR(llseek, "Couldn't write back new offset");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  STRACE_SUCCESS(llseek, "fd=%d, offset=%ld, whence=%d, new offset=%ld",
                 fd, offset64, whence, new_offset64);
  return syscall.SetReturn(memory, state, 0);
}

static void SetInodeNumber(const struct stat &info, linux32_stat *info32) {
  info32->st_ino = info.st_ino;
}

static void SetInodeNumber(const struct stat &info, linux32_stat64 *info32) {
  info32->__st_ino = static_cast<uint32_t>(info.st_ino);
  info32->st_ino = info.st_ino;
}

template <typename T>
void CopyStat(const struct stat &info, T *info32) {
  SetInodeNumber(info, info32);

  info32->st_dev = info.st_dev;
  info32->st_mode = info.st_mode;
  info32->st_nlink = static_cast<uint32_t>(info.st_nlink);
  info32->st_uid = info.st_uid;
  info32->st_gid = info.st_gid;
  info32->st_rdev = info.st_rdev;
  info32->st_size = info.st_size;
  info32->st_blksize = static_cast<int32_t>(info.st_blksize);
  info32->st_blocks = info.st_blocks;

  info32->st_atim.tv_sec = static_cast<uint32_t>(info.st_atim.tv_sec);
  info32->st_atim.tv_nsec = static_cast<uint32_t>(info.st_atim.tv_nsec);

  info32->st_mtim.tv_sec = static_cast<uint32_t>(info.st_mtim.tv_sec);
  info32->st_mtim.tv_nsec = static_cast<uint32_t>(info.st_mtim.tv_nsec);

  info32->st_ctim.tv_sec = static_cast<uint32_t>(info.st_ctim.tv_sec);
  info32->st_ctim.tv_nsec = static_cast<uint32_t>(info.st_ctim.tv_nsec);
}

// Emulate a `stat` system call.
template <typename T>
static Memory *SysStat(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  addr_t path = 0;
  addr_t buf = 0;
  if (!syscall.TryGetArgs(memory, state, &path, &buf)) {
    STRACE_ERROR(stat, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);

  } else if (!path || !buf) {
    STRACE_ERROR(stat, "NULL path or buf");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';

  if (path_len >= PATH_MAX) {
    STRACE_ERROR(stat, "Path name too long: %s", gPath);
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);

  // The string read does not end in a NUL-terminator; i.e. we read less
  // than `PATH_MAX`, but as much as we could without faulting, and we didn't
  // read the NUL char.
  } else if ('\0' != gPath[path_len]) {
    STRACE_ERROR(stat, "Non-NUL-terminated path");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct stat info = {};
  if (::stat(gPath, &info)) {
    auto err = errno;
    STRACE_ERROR(stat, "Can't stat path %s: %s", gPath, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  T info32 = {};
  CopyStat(info, &info32);

  if (TryWriteMemory(memory, buf, info32)) {
    STRACE_SUCCESS(stat, "path=%s", gPath);
    return syscall.SetReturn(memory, state, 0);
  } else {
    STRACE_ERROR(stat, "Can't write stat buff back to memory");
    return syscall.SetReturn(memory, state, -EFAULT);
  }
}

// Emulate an `lstat` system call.
template <typename T>
static Memory *SysLstat(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  addr_t path = 0;
  addr_t buf = 0;
  if (!syscall.TryGetArgs(memory, state, &path, &buf)) {
    STRACE_ERROR(lstat, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);

  } else if (!path || !buf) {
    STRACE_ERROR(lstat, "NULL path or buf");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';

  if (path_len >= PATH_MAX) {
    STRACE_ERROR(lstat, "Path name too long: %s", gPath);
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);

  // The string read does not end in a NUL-terminator; i.e. we read less
  // than `PATH_MAX`, but as much as we could without faulting, and we didn't
  // read the NUL char.
  } else if ('\0' != gPath[path_len]) {
    STRACE_ERROR(lstat, "Non-NUL-terminated path");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct stat info = {};
  if (lstat(gPath, &info)) {
    auto err = errno;
    STRACE_ERROR(lstat, "Can't lstat path %s: %s", gPath, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  T info32 = {};
  CopyStat(info, &info32);

  if (TryWriteMemory(memory, buf, info32)) {
    STRACE_SUCCESS(lstat, "path=%s", gPath);
    return syscall.SetReturn(memory, state, 0);
  } else {
    STRACE_ERROR(lstat, "Can't write stat buff back to memory");
    return syscall.SetReturn(memory, state, -EFAULT);
  }
}

// Emulate a an `fstat` system call.
template <typename T>
static Memory *SysFstat(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf)) {
    STRACE_ERROR(fstat, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  } else if (0 > fd) {
    STRACE_ERROR(fstat, "Bad fd %d", fd);
    return syscall.SetReturn(memory, state, -EBADFD);
  } else if (!buf) {
    STRACE_ERROR(fstat, "NULL buffer");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  struct stat info = {};
  if (fstat(fd, &info)) {
    auto err = errno;
    STRACE_ERROR(fstat, "Can't fstat fd %d: %s", fd, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  T info32 = {};
  CopyStat(info, &info32);

  if (TryWriteMemory(memory, buf, info32)) {
    STRACE_SUCCESS(fstat, "fd=%d", fd);
    return syscall.SetReturn(memory, state, 0);
  } else {
    STRACE_ERROR(fstat, "Can't write stat buff back to memory");
    return syscall.SetReturn(memory, state, -EFAULT);
  }
}

static Memory *SysGetCurrentWorkingDirectory(Memory *memory, State *state,
                                             const SystemCallABI &syscall) {
  addr_t buf = 0;
  addr_t size = 0;
  if (!syscall.TryGetArgs(memory, state, &buf, &size)) {
    STRACE_ERROR(getcwd, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!buf) {
    STRACE_ERROR(getcwd, "NULL pointer passed to buffer.");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  char *path_buf = &(gPath[0]);
  if (size >= PATH_MAX) {
    path_buf = nullptr;
  }

  auto ret = getcwd(path_buf, size);
  if (!ret) {
    auto err = errno;
    STRACE_ERROR(getcwd, "Couldn't get current working directory: %s",
                 strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  auto cwd_len = strlen(ret);
  if (size <= cwd_len) {
    if (ret != &(gPath[0])) {
      free(ret);
    }
    STRACE_ERROR(getcwd, "Buffer size %d < %d too small", size, cwd_len + 1);
    return syscall.SetReturn(memory, state, -ERANGE);
  }

  auto copied_len = CopyStringToMemory(memory, buf, ret, cwd_len);

  // Kernel returns the length of the buffer filled, including the NUL-
  // terminator.
  auto len_or_err = static_cast<int>(cwd_len + 1);

  if (copied_len == cwd_len) {
    STRACE_SUCCESS(getcwd, "path=%s, len=%u", ret, cwd_len);
  } else {
    STRACE_ERROR(getcwd, "Couldn't copy path to memory");
    len_or_err = -EFAULT;
  }

  if (ret != &(gPath[0])) {
    free(ret);
  }

  return syscall.SetReturn(memory, state, len_or_err);
}


static Memory *SysReadLink(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  addr_t path = 0;
  addr_t buf = 0;
  addr_t size = 0;
  if (!syscall.TryGetArgs(memory, state, &path, &buf, &size)) {
    STRACE_ERROR(readlink, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (0 > static_cast<addr_diff_t>(size)) {
    STRACE_ERROR(readlink, "Negative buffsize");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if (!buf) {
    STRACE_ERROR(readlink, "NULL buffer");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';
  if (!path_len) {
    STRACE_ERROR(readlink, "Could not read path");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto max_size = NumWritableBytes(memory, buf, size);
  if (!max_size) {
    STRACE_ERROR(readlink, "Could not write to buf");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto link_path = new char[max_size + 1];
  CopyFromMemory(memory, link_path, buf, max_size);

  auto ret = readlink(gPath, link_path, max_size);
  if (-1 == ret) {
    auto err = errno;
    delete [] link_path;
    STRACE_ERROR(
        readlink, "Could not read link of %s into buffer of size %u: %s",
        gPath, max_size, strerror(errno));
    return syscall.SetReturn(memory, state, -err);
  }

  link_path[max_size] = '\0';
  CopyToMemory(memory, buf, link_path, max_size);

  STRACE_SUCCESS(readlink, "path=%s, link=%s, len=%d", gPath, link_path, ret);
  delete [] link_path;

  return syscall.SetReturn(memory, state, ret);
}

}  // namespace
