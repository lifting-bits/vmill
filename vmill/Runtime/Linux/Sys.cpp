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

static Memory *SysExit(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int exit_code = EXIT_SUCCESS;
  if (!syscall.TryGetArgs(memory, state, &exit_code)) {
    STRACE_ERROR(exit, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  } else {
    STRACE_SUCCESS(exit, "status=%d", exit_code);
    __vmill_set_location(0, vmill::kTaskStoppedAtExit);
    return memory;
  }
}

//// Emulate an `gethostname` system call.
//static Memory *SysGetHostName(Memory *memory, State *state,
//                              const SystemCallABI &syscall) {
//  addr_t name = 0;
//  int len = 0;
//  if (!syscall.TryGetArgs(memory, state, &name, &len)) {
//    return syscall.SetReturn(memory, state, -EFAULT);
//  } else if (0 > len || HOST_NAME_MAX < len) {
//    return syscall.SetReturn(memory, state, -EINVAL);
//  }
//
//  gethostname(gHostName, HOST_NAME_MAX);
//  gHostName[HOST_NAME_MAX] = '\0';
//
//  auto actual_len = strlen(gHostName);
//  if (len < actual_len) {
//    return syscall.SetReturn(memory, state, -ENAMETOOLONG);
//  }
//
//  // Copy the maximum length host name, regardless of if the specified host
//  // name length is shorter.
//  auto copied_len = CopyStringToMemory(memory, name, gHostName, actual_len);
//  if (copied_len != actual_len) {
//    return syscall.SetReturn(memory, state, -EFAULT);
//  }
//
//  syscall.SetReturn(memory, state, 0);
//}


// Emulate an `sethostname` system call.
static Memory *SysSetHostName(Memory *memory, State *state,
                              const SystemCallABI &syscall) {
  addr_t name = 0;
  size_t len = 0;
  if (!syscall.TryGetArgs(memory, state, &name, &len)) {
    STRACE_ERROR(sethostname, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);

  } else if (HOST_NAME_MAX < len) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // Copy the maximum length host name, regardless of if the specified host
  // name length is shorter.
  auto name_len = CopyStringFromMemory(memory, name, gHostName, HOST_NAME_MAX);
  gHostName[HOST_NAME_MAX] = '\0';

  // The hostname passed to `sethostname` is a C string, and it is shorter
  // than the explicitly specified length.
  if (name_len < len) {
    STRACE_ERROR(sethostname, "Readable name length is %zu < %zu bytes",
                 name_len, len);
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);
  }

  auto ret = sethostname(gHostName, len);
  if (!ret) {
    STRACE_SUCCESS(sethostname, "name=%s, len=%zu", gHostName, len);
    return syscall.SetReturn(memory, state, 0);
  } else {
    auto err = errno;
    STRACE_ERROR(sethostname, "Can't set host name to %s: %s",
                 gHostName, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }
}

//static void SetDomainName(const struct utsname &, linux_oldold_utsname *) {}
//static void SetDomainName(const struct utsname &, linux_old_utsname *) {}
static void SetDomainName(const struct utsname &info,
                          linux_new_utsname *info_compat) {
  memcpy(&(info_compat->domainname[0]), &(info.domainname[0]),
         sizeof(info_compat->domainname));
}

// Emulate the `uname` system calls.
template <typename T>
static Memory *SysUname(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  addr_t buf = 0;
  if (!syscall.TryGetArgs(memory, state, &buf)) {
    STRACE_ERROR(uname, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct utsname info = {};
  if (-1 == uname(&info)) {
    auto err = errno;
    STRACE_ERROR(uname, "Couldn't get uname: %s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  linux_new_utsname compat = {};
  memcpy(&(compat.sysname[0]), "Linux", 6);
  memcpy(&(compat.nodename[0]), &(info.nodename[0]), sizeof(compat.nodename));
  memcpy(&(compat.release[0]), &(info.release[0]), sizeof(compat.release));
  memcpy(&(compat.version[0]), &(info.version[0]), sizeof(compat.version));
#if defined(VMILL_RUNTIME_AARCH64)
  memcpy(&(compat.machine[0]), "aarch64", 8);
#elif defined(VMILL_RUNTIME_X86)
# if 32 == VMILL_RUNTIME_X86
  memcpy(&(compat.machine[0]), "i686", 6);
# else
  memcpy(&(compat.machine[0]), "x86_64", 7);
# endif
#else
# error "Add architecture name here!"
#endif

  SetDomainName(info, &compat);

  if (TryWriteMemory(memory, buf, info)) {
    STRACE_SUCCESS(uname, "sysname=%s, nodename=%s, release=%s, version=%s",
                   info.sysname, info.nodename, info.release, info.version);
    return syscall.SetReturn(memory, state, 0);
  } else {
    STRACE_ERROR(uname, "Couldn't write uname info");
    return syscall.SetReturn(memory, state, -EFAULT);
  }
}

// Emulate an `getuid` system call.
static Memory *SysGetUserId(Memory *memory, State *state,
                            const SystemCallABI &syscall) {
  auto id = getuid();
  STRACE_SUCCESS(getuid, "user id=%u", id);
  return syscall.SetReturn(memory, state, id);
}

// Emulate an `geteuid` system call.
static Memory *SysGetEffectiveUserId(Memory *memory, State *state,
                                     const SystemCallABI &syscall) {
  auto id = geteuid();
  STRACE_SUCCESS(geteuid, "effective user id=%u", id);
  return syscall.SetReturn(memory, state, id);
}


// Emulate an `getgid` system call.
static Memory *SysGetGroupId(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  auto id = getgid();
  STRACE_SUCCESS(getgid, "group id=%u", id);
  return syscall.SetReturn(memory, state, id);
}

// Emulate an `getegid` system call.
static Memory *SysGetEffectiveGroupId(Memory *memory, State *state,
                                      const SystemCallABI &syscall) {
  auto id = getegid();
  STRACE_SUCCESS(getegid, "effective group id=%u", id);
  return syscall.SetReturn(memory, state, id);
}

template <typename T>
static Memory *SysGetRlimit(Memory *memory, State *state,
                            const SystemCallABI &syscall) {
  int resource = 0;
  addr_t rlim_addr = 0;
  if (!syscall.TryGetArgs(memory, state, &resource, &rlim_addr)) {
    STRACE_ERROR(rlimit, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct rlimit limit = {};
  if (0 != getrlimit(resource, &limit)) {
    auto err = errno;
    STRACE_ERROR(rlimit, "Couldn't get rlimit: %s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  T compat_limit = {};
  using LimT = decltype(compat_limit.rlim_cur);

  compat_limit.rlim_cur = static_cast<LimT>(std::min<rlim_t>(
      std::numeric_limits<LimT>::max(),
      limit.rlim_cur));

  compat_limit.rlim_max = static_cast<LimT>(std::min<rlim_t>(
        std::numeric_limits<LimT>::max(),
        limit.rlim_max));

  if (!TryWriteMemory(memory, rlim_addr, compat_limit)) {
    STRACE_ERROR(rlimit, "Couldn't write limit back to memory");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  STRACE_SUCCESS(rlimit, "resource=%d, rlim_cur=%lx, rlim_max=%lx",
                 resource, limit.rlim_cur, limit.rlim_max);
  return syscall.SetReturn(memory, state, 0);
}

template <typename T>
static Memory *SysGetRESUserId(Memory *memory, State *state,
                               const SystemCallABI &syscall) {
  addr_t rid = 0;
  addr_t eid = 0;
  addr_t sid = 0;
  if (!syscall.TryGetArgs(memory, state, &rid, &eid, &sid)) {
    STRACE_ERROR(getresuid, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  uid_t real_uid = 0;
  uid_t effective_uid = 0;
  uid_t set_uid = 0;
  auto ret = getresuid(&real_uid, &effective_uid, &set_uid);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(getresuid, "%s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  if (rid) {
    if (!TryWriteMemory(memory, rid, static_cast<uint32_t>(real_uid))) {
      STRACE_ERROR(getresuid, "Coudn't write real uid to %" PRIxADDR, rid);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (eid) {
    if (!TryWriteMemory(memory, eid, static_cast<uint32_t>(effective_uid))) {
      STRACE_ERROR(getresuid, "Coudn't write effective uid to %" PRIxADDR, eid);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (sid) {
    if (!TryWriteMemory(memory, sid, static_cast<uint32_t>(set_uid))) {
      STRACE_ERROR(getresuid, "Coudn't write setsid uid to %" PRIxADDR, sid);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(getresuid, "real_uid=%u, effective_uid=%u, set_uid=%u",
                 real_uid, effective_uid, set_uid);

  return syscall.SetReturn(memory, state, 0);
}


template <typename T>
static Memory *SysGetRESGroupId(Memory *memory, State *state,
                               const SystemCallABI &syscall) {
  addr_t rid = 0;
  addr_t eid = 0;
  addr_t sid = 0;
  if (!syscall.TryGetArgs(memory, state, &rid, &eid, &sid)) {
    STRACE_ERROR(getresgid, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  gid_t real_gid = 0;
  gid_t effective_gid = 0;
  gid_t set_gid = 0;
  auto ret = getresgid(&real_gid, &effective_gid, &set_gid);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(getresgid, "%s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  if (rid) {
    if (!TryWriteMemory(memory, rid, static_cast<uint32_t>(real_gid))) {
      STRACE_ERROR(getresgid, "Coudn't write real gid to %" PRIxADDR, rid);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (eid) {
    if (!TryWriteMemory(memory, eid, static_cast<uint32_t>(effective_gid))) {
      STRACE_ERROR(getresgid, "Coudn't write effective gid to %" PRIxADDR, eid);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (sid) {
    if (!TryWriteMemory(memory, sid, static_cast<uint32_t>(set_gid))) {
      STRACE_ERROR(getresgid, "Coudn't write setsid gid to %" PRIxADDR, sid);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(getresgid, "real_gid=%u, effective_gid=%u, set_gid=%u",
                 real_gid, effective_gid, set_gid);

  return syscall.SetReturn(memory, state, 0);
}

template <typename InfoT>
static Memory *SysGetSysInfo(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  addr_t info_addr = 0;
  if (!syscall.TryGetArgs(memory, state, &info_addr)) {
    STRACE_ERROR(sysinfo, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  InfoT compat_info = {};
  if (!TryReadMemory(memory, info_addr, &compat_info)) {
    STRACE_ERROR(sysinfo, "Couldn't read info=%" PRIxADDR, info_addr);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct sysinfo info = {};
  auto ret = sysinfo(&info);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(sysinfo, "%s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  compat_info.uptime = static_cast<addr_diff_t>(info.uptime);
  compat_info.loads[0] = static_cast<addr_t>(info.loads[0]);
  compat_info.loads[1] = static_cast<addr_t>(info.loads[1]);
  compat_info.loads[1] = static_cast<addr_t>(info.loads[2]);
  compat_info.totalram = static_cast<addr_t>(info.totalram);
  compat_info.freeram = static_cast<addr_t>(info.freeram);
  compat_info.sharedram = static_cast<addr_t>(info.sharedram);
  compat_info.bufferram = static_cast<addr_t>(info.bufferram);
  compat_info.totalswap = static_cast<addr_t>(info.totalswap);
  compat_info.freeswap = static_cast<addr_t>(info.freeswap);
  compat_info.procs = info.procs;
  compat_info.totalhigh = static_cast<addr_t>(info.totalhigh);
  compat_info.freehigh = static_cast<addr_t>(info.freehigh);
  compat_info.mem_unit = info.mem_unit;

  if (!TryWriteMemory(memory, info_addr, compat_info)) {
    STRACE_ERROR(sysinfo, "Couldn't write info=%" PRIxADDR, info_addr);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  STRACE_SUCCESS(sysinfo, "uptime=%lu, loads=[%lu, %lu, %lu], ...",
                 info.uptime, info.loads[0], info.loads[1], info.loads[2]);
  return syscall.SetReturn(memory, state, 0);
}

}  // namespace
