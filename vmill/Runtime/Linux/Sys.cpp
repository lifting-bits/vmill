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
    __vmill_free_address_space(memory);
    __vmill_free_state(state);
    return nullptr;
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
    STRACE_ERROR(sethostname, "Readable name length is %d < %d bytes",
                 name_len, len);
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);
  }

  auto ret = sethostname(gHostName, len);
  if (!ret) {
    STRACE_SUCCESS(sethostname, "name=%s, len=%d", gHostName, len);
    return syscall.SetReturn(memory, state, 0);
  } else {
    STRACE_ERROR(sethostname, "Can't set host name to %s: %s",
                 gHostName, strerror(errno));
    return syscall.SetReturn(memory, state, -errno);
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
    STRACE_ERROR(uname, "Couldn't get uname: %s", strerror(errno));
    return syscall.SetReturn(memory, state, -errno);
  }

  linux_new_utsname compat = {};
  memcpy(&(compat.sysname[0]), &(info.sysname[0]), sizeof(compat.sysname));
  memcpy(&(compat.nodename[0]), &(info.nodename[0]), sizeof(compat.nodename));
  memcpy(&(compat.release[0]), &(info.release[0]), sizeof(compat.release));
  memcpy(&(compat.version[0]), &(info.version[0]), sizeof(compat.version));
  memcpy(&(compat.machine[0]), &(info.machine[0]), sizeof(compat.machine));
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

}  // namespace
