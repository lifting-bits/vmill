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

// Intermediate buffer for copying data to/from the runtime memory and the
// emulated process memory.
static uint8_t gIOBuffer[kIOBufferSize + 1] = {};

// Intermediate buffer for holding file system paths, used in various syscalls.
static char gPath[PATH_MAX + 1] = {};
static char gPathAt[PATH_MAX + 1] = {};

// Intermediate buffer for holding host names.
static char gHostName[HOST_NAME_MAX + 1] = {};

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
    case 13: return SysTime(memory, state, syscall);
    case 20: return SysGetProcessId(memory, state, syscall);
    case 24: return SysGetUserId(memory, state, syscall);
    case 33: return SysAccess(memory, state, syscall);
    case 37: return SysKill(memory, state, syscall);
    case 39: return SysMakeDirectory(memory, state, syscall);
    case 40: return SysRemoveDirectory(memory, state, syscall);
    case 41: return SysDup(memory, state, syscall);
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
    case 78:
      return SysGetTimeOfDay<linux32_timeval, linux32_timezone>(
          memory, state, syscall);
    case 79:
      return SysSetTimeOfDay<linux32_timeval, linux32_timezone>(
          memory, state, syscall);
    case 85: return SysReadLink(memory, state, syscall);
    case 90: return SysMmap(memory, state, syscall);
    case 91: return SysMunmap(memory, state, syscall);
    case 102: return SysSocketCall<uint32_t>(memory, state, syscall);
    case 106: return SysStat<linux32_stat>(memory, state, syscall);
    case 107: return SysLstat<linux32_stat>(memory, state, syscall);
    case 108: return SysFstat<linux32_stat>(memory, state, syscall);
    case 109: return SysUname<linux_old_utsname>(memory, state, syscall);
    case 116: return SysGetSysInfo<linux_sysinfo>(memory, state, syscall);
    case 120: return SysCloneB(memory, state, syscall);
    case 122: return SysUname<linux_new_utsname>(memory, state, syscall);
    case 125: return SysMprotect(memory, state, syscall);
    case 140: return SysLlseek(memory, state, syscall);
    case 145: return SysReadV(memory, state, syscall);
    case 146: return SysWriteV(memory, state, syscall);
    case 165: return SysGetRESUserId<uid_t>(memory, state, syscall);
    case 168: return SysPoll(memory, state, syscall);
    case 171: return SysGetRESGroupId<gid_t>(memory, state, syscall);
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
    case 209: return SysGetRESUserId<uint32_t>(memory, state, syscall);
    case 211: return SysGetRESGroupId<uint32_t>(memory, state, syscall);
    case 220: return SysGetDirEntries64(memory, state, syscall);
    case 221: return SysFcntl64(memory, state, syscall);
    case 224: return SysGetThreadId(memory, state, syscall);
    case 240: return SysFutex<linux32_timespec>(memory, state, syscall);
    case 243:
      return SysSetThreadArea<linux_x86_user_desc>(memory, state, syscall);
    case 258: return SysSetThreadIdAddress(memory, state, syscall);
    case 265: return SysClockGetTime<linux32_timespec>(memory, state, syscall);
    case 266:
      return SysClockGetResolution<linux32_timespec>(memory, state, syscall);
    case 268: return SysStatFs64<linux32_statfs64>(memory, state, syscall);
    case 269: return SysFStatFs64<linux32_statfs64>(memory, state, syscall);
    case 272: return SysFAdvise<int32_t, int32_t>(memory, state, syscall);
    case 295: return SysOpenAt(memory, state, syscall);
    case 296: return SysMakeDirectoryAt(memory, state, syscall);
    case 300: return SysFStatAt<linux32_stat64>(memory, state, syscall);
    case 305: return SysReadLinkAt(memory, state, syscall);
    case 307: return SysFAccessAt(memory, state, syscall);
    case 323: return SysEventFd(memory, state, syscall);
    case 328: return SysEventFd2(memory, state, syscall);
    default:
      STRACE_ERROR(unsupported, ANSI_COLOR_MAGENTA "nr=%" PRIuADDR,
                   syscall_num);
      return syscall.SetReturn(memory, state, 0);
  }
}

# if 64 == VMILL_RUNTIME_X86
// 64-bit system call dispatcher for `int 0x80` and `sysenter` system call
// entry points.
static Memory *AMD64SystemCall(Memory *memory, State *state,
                               const SystemCallABI &syscall) {
  auto syscall_num = syscall.GetSystemCallNum(memory, state);
  STRACE_SYSCALL_NUM(syscall_num);
  switch (syscall_num) {
    case 0: return SysRead(memory, state, syscall);
    case 1: return SysWrite(memory, state, syscall);
    case 2: return SysOpen(memory, state, syscall);
    case 3: return SysClose(memory, state, syscall);
    case 4: return SysStat<struct linux64_stat>(memory, state, syscall);
    case 5: return SysFstat<struct linux64_stat>(memory, state, syscall);
    case 6: return SysLstat<struct linux64_stat>(memory, state, syscall);
    case 7: return SysPoll(memory, state, syscall);
    case 8: return SysLseek(memory, state, syscall);
    case 9: return SysMmap(memory, state, syscall);
    case 10: return SysMprotect(memory, state, syscall);
    case 11: return SysMunmap(memory, state, syscall);
    case 12: return SysBrk(memory, state, syscall);
    case 13:
      STRACE_ERROR(rt_sigaction, "Suppressed");
      return syscall.SetReturn(memory, state, 0);
    case 14:
      STRACE_ERROR(rt_sigprocmask, "Suppressed");
      return syscall.SetReturn(memory, state, 0);
    case 16: return SysIoctl(memory, state, syscall);
    case 19: return SysReadV(memory, state, syscall);
    case 20: return SysWriteV(memory, state, syscall);
    case 21: return SysAccess(memory, state, syscall);
    case 32: return SysDup(memory, state, syscall);
    case 39: return SysGetProcessId(memory, state, syscall);
    case 41: return SysSocket(memory, state, syscall);
    case 42: return SysConnect(memory, state, syscall);
    case 43: return SysAccept(memory, state, syscall);
    case 44: return SysSendTo(memory, state, syscall);
    case 45: return SysRecvFrom(memory, state, syscall);
    case 46: return SysSendMsg<struct linux64_msghdr, struct linux64_iovec>(
        memory, state, syscall);
    case 47: return SysRecvMsg<struct linux64_msghdr, struct linux64_iovec>(
        memory, state, syscall);
    case 48: return SysShutdown(memory, state, syscall);
    case 49: return SysBind(memory, state, syscall);
    case 50: return SysListen(memory, state, syscall);
    case 51: return SysGetSockName(memory, state, syscall);
    case 52: return SysGetPeerName(memory, state, syscall);
    case 53: return SysSocketPair(memory, state, syscall);
    case 54: return SysSetSockOpt(memory, state, syscall);
    case 55: return SysGetSockOpt(memory, state, syscall);
    case 56: return SysCloneA(memory, state, syscall);
    case 60: return SysExit(memory, state, syscall);
    case 62: return SysKill(memory, state, syscall);
    case 63: return SysUname<linux_new_utsname>(memory, state, syscall);
    case 78: return SysGetDirEntries64(memory, state, syscall);
    case 97: return SysGetRlimit<linux_rlimit>(memory, state, syscall);
    case 102: return SysGetUserId(memory, state, syscall);
    case 158: return SysArchPrctl(memory, state, syscall);
    case 202: return SysFutex<linux64_timespec>(memory, state, syscall);
    case 218: return SysSetThreadIdAddress(memory, state, syscall);
/*
    case 13: return SysTime(memory, state, syscall);
    case 24: return SysGetUserId(memory, state, syscall);
    case 39: return SysMakeDirectory(memory, state, syscall);
    case 40: return SysRemoveDirectory(memory, state, syscall);
    case 47: return SysGetGroupId(memory, state, syscall);
    case 49: return SysGetEffectiveUserId(memory, state, syscall);
    case 50: return SysGetEffectiveGroupId(memory, state, syscall);
    case 59: return SysUname<linux_oldold_utsname>(memory, state, syscall);
    case 64: return SysGetParentProcessId(memory, state, syscall);
    case 65: return SysGetProcessGroupId(memory, state, syscall);
    case 74: return SysSetHostName(memory, state, syscall);
    case 76: return SysGetRlimit<linux_rlimit>(memory, state, syscall);
    case 78:
      return SysGetTimeOfDay<linux32_timeval, linux32_timezone>(
          memory, state, syscall);
    case 79:
      return SysSetTimeOfDay<linux32_timeval, linux32_timezone>(
          memory, state, syscall);
    case 85: return SysReadLink(memory, state, syscall);
    case 102: return SysSocketCall<uint32_t>(memory, state, syscall);
    case 109: return SysUname<linux_old_utsname>(memory, state, syscall);
    case 116: return SysGetSysInfo<linux_sysinfo>(memory, state, syscall);
    case 120: return SysCloneB(memory, state, syscall);

    case 165: return SysGetRESUserId<uid_t>(memory, state, syscall);
    case 171: return SysGetRESGroupId<gid_t>(memory, state, syscall);
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
    case 209: return SysGetRESUserId<uint32_t>(memory, state, syscall);
    case 211: return SysGetRESGroupId<uint32_t>(memory, state, syscall);
    case 220: return SysGetDirEntries64(memory, state, syscall);
    case 221: return SysFcntl64(memory, state, syscall);
    case 224: return SysGetThreadId(memory, state, syscall);
    case 240: return SysFutex<linux32_timespec>(memory, state, syscall);
    case 243:
      return SysSetThreadArea<linux_x86_user_desc>(memory, state, syscall);
    case 265: return SysClockGetTime<linux32_timespec>(memory, state, syscall);
    case 266:
      return SysClockGetResolution<linux32_timespec>(memory, state, syscall);
    case 268: return SysStatFs64<linux32_statfs64>(memory, state, syscall);
    case 269: return SysFStatFs64<linux32_statfs64>(memory, state, syscall);
    case 272: return SysFAdvise<int32_t, int32_t>(memory, state, syscall);
    case 295: return SysOpenAt(memory, state, syscall);
    case 296: return SysMakeDirectoryAt(memory, state, syscall);
    case 300: return SysFStatAt<linux32_stat64>(memory, state, syscall);
    case 305: return SysReadLinkAt(memory, state, syscall);
    case 307: return SysFAccessAt(memory, state, syscall);
    case 323: return SysEventFd(memory, state, syscall);
    case 328: return SysEventFd2(memory, state, syscall);
*/
    default:
      STRACE_ERROR(unsupported, ANSI_COLOR_MAGENTA "nr=%" PRIuADDR,
                   syscall_num);
      return syscall.SetReturn(memory, state, 0);
  }
}
# endif  // 64 == VMILL_RUNTIME_X86
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
    case 169:
      return SysGetTimeOfDay<struct timeval, struct timezone>(
          memory, state, syscall);
    case 170:
      return SysSetTimeOfDay<struct timeval, struct timezone>(
          memory, state, syscall);
    case 78: return SysReadLinkAt(memory, state, syscall);
    case 222: return SysMmap(memory, state, syscall);
    case 215: return SysMunmap(memory, state, syscall);
    case 96: return SysSetThreadIdAddress(memory, state, syscall);
#if 0
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
    case 243: return SysSetThreadArea<linux_x86_user_desc>(
        memory, state, syscall);
#endif
    default:
      STRACE_ERROR(unsupported, ANSI_COLOR_MAGENTA "nr=%" PRIuADDR,
                   syscall_num);
      return syscall.SetReturn(memory, state, 0);
  }
}

#endif  // VMILL_RUNTIME_AARCH64

}  // namespace
