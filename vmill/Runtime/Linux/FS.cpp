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
    STRACE_ERROR(access, "Cann't access %s: %s", gPath, strerror(errno));
    return syscall.SetReturn(memory, state, -errno);
  } else {
    STRACE_SUCCESS(access, "path=%s, type=%d, ret=%d", gPath, type, ret);
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
    STRACE_ERROR(llseek, "fd=%d, offset=%ld, whence=%d: %s",
                 fd, offset64, whence, strerror(errno));
    return syscall.SetReturn(memory, state, -errno);
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
    STRACE_ERROR(stat, "Can't stat path %s: %s", gPath, strerror(errno));
    return syscall.SetReturn(memory, state, -errno);
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
    STRACE_ERROR(lstat, "Can't lstat path %s: %s", gPath, strerror(errno));
    return syscall.SetReturn(memory, state, -errno);
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
    STRACE_ERROR(fstat, "Can't fstat fd %d: %s", fd, strerror(errno));
    return syscall.SetReturn(memory, state, -errno);
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

}  // namespace
