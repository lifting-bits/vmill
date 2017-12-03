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

// Emulate an `getpid` system call.
static Memory *SysGetProcessId(Memory *memory, State *state,
                               const SystemCallABI &syscall) {
  //auto id = getpid();
  STRACE_SUCCESS(getpid, "process id=%u", kProcessId);
  return syscall.SetReturn(memory, state, kProcessId);
}

// Emulate an `getpid` system call.
static Memory *SysGetParentProcessId(Memory *memory, State *state,
                               const SystemCallABI &syscall) {
  //auto id = getppid();
  STRACE_SUCCESS(getppid, "parent process id=%u", kParentProcessId);
  return syscall.SetReturn(memory, state, kParentProcessId);
}

// Emulate an `getpgrp` system call.
static Memory *SysGetProcessGroupId(Memory *memory, State *state,
                                    const SystemCallABI &syscall) {
  //auto id = getpgrp();
  STRACE_SUCCESS(getpgrp, "process group id=0", kParentProcessGroupId);
  return syscall.SetReturn(memory, state, kParentProcessGroupId);
}

// Emulate an `gettid` system call.
static Memory *SysGetThreadId(Memory *memory, State *state,
                              const SystemCallABI &syscall) {
  auto current = __vmill_current();
  auto id = current->tid;
  STRACE_SUCCESS(gettid, "thread id=%u", id);
  return syscall.SetReturn(memory, state, id);
}

// Emulate an `kill` system call.
static Memory *SysKill(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  pid_t pid = 0;
  int signum = 0;
  if (!syscall.TryGetArgs(memory, state, &pid, &signum)) {
    STRACE_ERROR(kill, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto task = __vmill_current();
  if (-1 == pid || 0 == pid || kProcessId == pid) {
    STRACE_ERROR(kill, "pid=%u, signal=%d, suppressed", pid, signum);
    return syscall.SetReturn(memory, state, 0);

  } else {
    auto ret = kill(pid, signum);
    if (-1 == ret) {
      auto err = errno;
      STRACE_ERROR(kill, "pid=%u, signal=%d: %s", pid, signum, strerror(err));
      return syscall.SetReturn(memory, state, -err);

    } else {
      STRACE_SUCCESS(kill, "pid=%u, signal=%d", pid, signum);
      return syscall.SetReturn(memory, state, 0);
    }
  }

}

}  // namespace
