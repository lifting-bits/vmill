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
  auto id = getpid();
  STRACE_SUCCESS(getpid, "process id=%u", id);
  return syscall.SetReturn(memory, state, id);
}

// Emulate an `getpid` system call.
static Memory *SysGetParentProcessId(Memory *memory, State *state,
                               const SystemCallABI &syscall) {
  auto id = getppid();
  STRACE_SUCCESS(getppid, "parent process id=%u", id);
  return syscall.SetReturn(memory, state, id);
}

// Emulate an `getpid` system call.
static Memory *SysGetProcessGroupId(Memory *memory, State *state,
                                    const SystemCallABI &syscall) {
  auto id = getpgrp();
  STRACE_SUCCESS(getpgrp, "process group id=%u", id);
  return syscall.SetReturn(memory, state, id);
}

// Emulate an `gettid` system call.
static Memory *SysGetThreadId(Memory *memory, State *state,
                               const SystemCallABI &syscall) {
  auto id = getpid();  // TODO(pag): Emulate `gettid`?
  STRACE_SUCCESS(gettid, "thread id=%u", id);
  return syscall.SetReturn(memory, state, id);
}

}  // namespace
