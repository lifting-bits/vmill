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

#ifndef AT_FDCWD
# define AT_FDCWD (-100)
#endif

#ifndef AT_SYMLINK_NOFOLLOW
# define AT_SYMLINK_NOFOLLOW 0x100
#endif

#ifndef AT_SYMLINK_FOLLOW
# define AT_SYMLINK_FOLLOW 0x400
#endif

namespace {

// Impossible flags to simultaneously handle for `*at` related syscalls
// (e.g. `openat`, `fstatat`, etc.).
static constexpr int gAtFollowNoFollow = AT_SYMLINK_FOLLOW |
                                         AT_SYMLINK_NOFOLLOW;

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
  info32->st_blksize = static_cast<decltype(info32->st_blksize)>(
      info.st_blksize);
  info32->st_blocks = info.st_blocks;

  using sec_t = decltype(info32->st_ctim.tv_sec);
  using nsec_t = decltype(info32->st_ctim.tv_nsec);

  info32->st_atim.tv_sec = static_cast<sec_t>(info.st_atim.tv_sec);
  info32->st_atim.tv_nsec = static_cast<nsec_t>(info.st_atim.tv_nsec);

  info32->st_mtim.tv_sec = static_cast<sec_t>(info.st_mtim.tv_sec);
  info32->st_mtim.tv_nsec = static_cast<nsec_t>(info.st_mtim.tv_nsec);

  info32->st_ctim.tv_sec = static_cast<sec_t>(info.st_ctim.tv_sec);
  info32->st_ctim.tv_nsec = static_cast<nsec_t>(info.st_ctim.tv_nsec);
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

// Get the base path associated with a `*at` systemcall (e.g. `openat`,
// `fstatat`, etc.).
static char *GetBasePathAt(int fd) {
  if (AT_FDCWD == fd) {
    auto ret = getcwd(gPathAt, PATH_MAX);
    gPathAt[PATH_MAX] = '\0';
    if (!ret) {
      return nullptr;
    }

  } else if (0 > fd) {
    return nullptr;
  }

#ifndef __linux__
# error "Cannot access `/proc/` file system on non-Linux machines."
#endif

  // TODO(pag): This is linux specific.
  char fd_path[64] = {};
  sprintf(&(fd_path[0]), "/proc/self/fd/%d", fd);

  auto ret = readlink(fd_path, gPathAt, PATH_MAX);
  gPathAt[PATH_MAX] = '\0';
  if (-1 == ret) {
    return nullptr;
  }
  gPathAt[ret] = '\0';
  return gPathAt;
}

static char *GetPathAt(int fd, char *path, int flags) {
  if (path[0] == '/') {
    return path;
  }

  auto base_path = GetBasePathAt(fd);
  if (!base_path) {
    return nullptr;
  }

  auto iobuf = reinterpret_cast<char *>(&(gIOBuffer[0]));

  if (!(flags & AT_SYMLINK_NOFOLLOW) | (flags | AT_SYMLINK_FOLLOW)) {
    auto ret = readlink(base_path, iobuf, PATH_MAX);
    iobuf[PATH_MAX] = '\0';
    if (-1 == ret) {
      return nullptr;
    }
    iobuf[ret] = '\0';
    base_path = iobuf;
  }

  auto base_path_len = strlen(base_path);
  if (base_path != iobuf) {
    memcpy(iobuf, base_path, base_path_len);
  }
  iobuf[base_path_len] = '/';

  auto path_len = strlen(path);
  memcpy(&(iobuf[base_path_len + 1]), path, path_len);

  return iobuf;
}

// Emulate a `fstatat` system call.
template <typename T>
static Memory *SysFStatAt(Memory *memory, State *state,
                          const SystemCallABI &syscall) {
  int fd = 0;
  addr_t path = 0;
  addr_t buf = 0;
  int flag = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &path, &buf, &flag)) {
    STRACE_ERROR(fstatat, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);

  } else if (!path || !buf) {
    STRACE_ERROR(fstatat, "NULL path or buf");
    return syscall.SetReturn(memory, state, -EINVAL);

  } else if (gAtFollowNoFollow == (flag & gAtFollowNoFollow)) {
    STRACE_ERROR(fstatat, "AT_SYMLINK_FOLLOW|AT_SYMLINK_NOFOLLOW in flags");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';

  if (path_len >= PATH_MAX) {
    STRACE_ERROR(fstatat, "Path name too long: %s", gPath);
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);

  // The string read does not end in a NUL-terminator; i.e. we read less
  // than `PATH_MAX`, but as much as we could without faulting, and we didn't
  // read the NUL char.
  } else if ('\0' != gPath[path_len]) {
    STRACE_ERROR(fstatat, "Non-NUL-terminated path");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto final_path = GetPathAt(fd, gPath, flag);
  if (!final_path) {
    STRACE_ERROR(fstatat, "Cannot find base path for fd %d and ", fd);
    return syscall.SetReturn(memory, state, -EBADFD);
  }

  struct stat info = {};
  if (::stat(final_path, &info)) {
    auto err = errno;
    STRACE_ERROR(fstatat, "Can't stat path %s (final=%s): %s",
                 gPath, final_path, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  T info_compat = {};
  CopyStat(info, &info_compat);

  if (TryWriteMemory(memory, buf, info_compat)) {
    STRACE_SUCCESS(fstatat, "fd=%d, path=%s, flag=%x", fd, gPath, flag);
    return syscall.SetReturn(memory, state, 0);
  } else {
    STRACE_ERROR(fstatat, "Can't write stat buff back to memory");
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

static Memory *SysReadLinkAt(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  int fd = 0;
  addr_t path = 0;
  addr_t buf = 0;
  addr_t size = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &path, &buf, &size)) {
    STRACE_ERROR(readlinkat, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (0 > static_cast<addr_diff_t>(size)) {
    STRACE_ERROR(readlinkat, "Negative buffsize");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if (!buf) {
    STRACE_ERROR(readlinkat, "NULL buffer");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';
  if (!path_len) {
    STRACE_ERROR(readlinkat, "Could not read path");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto max_size = NumWritableBytes(memory, buf, size);
  if (!max_size) {
    STRACE_ERROR(readlinkat, "Could not write to buf");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto link_path = new char[max_size + 1];
  CopyFromMemory(memory, link_path, buf, max_size);

  auto ret = readlinkat(fd, gPath, link_path, max_size);
  if (-1 == ret) {
    auto err = errno;
    delete [] link_path;
    STRACE_ERROR(
        readlinkat, "Could not read link of %s into buffer of size %u: %s",
        gPath, max_size, strerror(errno));
    return syscall.SetReturn(memory, state, -err);
  }

  link_path[max_size] = '\0';
  CopyToMemory(memory, buf, link_path, max_size);

  STRACE_SUCCESS(readlinkat, "fd=%d, path=%s, link=%s, len=%d",
                 fd, gPath, link_path, ret);
  delete [] link_path;

  return syscall.SetReturn(memory, state, ret);
}

static Memory *SysGetDirEntries64(Memory *memory, State *state,
                                  const SystemCallABI &syscall) {
  int fd = -1;
  addr_t dirent = 0;
  unsigned count = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &dirent, &count)) {
    STRACE_ERROR(getdents64, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!CanWriteMemory(memory, dirent, count)) {
    STRACE_ERROR(getdents64, "Can't write count=%u bytes to dirent=%" PRIxADDR,
                 count, dirent);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto pos = lseek(fd, 0, SEEK_CUR);
  auto our_fd = dup(fd);
  if (-1 == our_fd) {
    auto err = errno;
    STRACE_ERROR(getdents64, "Can't read directory fd=%d entries (1): %s",
                 fd, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  auto dir = fdopendir(our_fd);
  if (!dir) {
    auto err = errno;
    STRACE_ERROR(getdents64, "Can't read directory fd=%d entries (2): %s",
                 fd, strerror(err));

    close(our_fd);
    return syscall.SetReturn(memory, state, -err);
  }

  seekdir(dir, pos);

  long int ret = 0;
  int num_entries = 0;
  for (auto written = 0U; ; ) {
    if (written) {
      pos = telldir(dir);
    }

    auto our_entry = readdir(dir);
    if (!our_entry) {
      break;
    }

    struct linux_dirent64 entry = {};


    auto name_len = strlen(our_entry->d_name);
    auto entry_addr = dirent + written;
    auto to_write = __builtin_offsetof(struct linux_dirent64, d_name);
    to_write += name_len + sizeof(char); // For NUL-byte.

    // Align it.
    if (0 != (to_write % alignof(entry.d_ino))) {
      to_write += alignof(entry.d_ino) - (to_write % alignof(entry.d_ino));
    }

    // Don't write beyond the end of the provided buffer.
    if ((written + to_write) > count) {
      break;
    }

    entry.d_ino = static_cast<decltype(entry.d_ino)>(our_entry->d_ino);
    entry.d_off = static_cast<decltype(entry.d_off)>(our_entry->d_off);
    entry.d_reclen = static_cast<uint16_t>(to_write);
    entry.d_type = static_cast<decltype(entry.d_type)>(our_entry->d_type);
    entry.d_name[0] = '\0';

    TryWriteMemory(memory, entry_addr, entry);
    CopyStringToMemory(memory, entry_addr + sizeof(struct linux_dirent64),
                       our_entry->d_name, name_len);

    written += to_write;
    ret = static_cast<long int>(written);
    num_entries += 1;
  }

  lseek(fd, pos, SEEK_SET);
  closedir(dir);

  STRACE_SUCCESS(
      getdents64, "Read %ld of count=%u bytes (%d entries) from dir fd=%d",
      ret, count, num_entries, fd);
  return syscall.SetReturn(memory, state, ret);
}

}  // namespace
