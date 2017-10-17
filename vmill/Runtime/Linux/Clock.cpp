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

// Emulate a 32-bit `gettimeofday` system call.
static Memory *SysGetTimeOfDay32(Memory *memory, State *state,
                                 const SystemCallABI &syscall) {
  addr_t tv_addr = 0;
  addr_t tz_addr = 0;

  if (!syscall.TryGetArgs(memory, state, &tv_addr, &tz_addr)) {
    STRACE_ERROR(gettimeofday, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct timeval tv = {};
  struct timezone tz = {};
  gettimeofday(&tv, &tz);
  auto ret = errno;

  if (tv_addr) {
    linux32_timeval tv_compat = {
        .tv_sec = static_cast<uint32_t>(tv.tv_sec),
        .tv_usec = static_cast<uint32_t>(tv.tv_usec),
    };
    if (!TryWriteMemory(memory, tv_addr, &tv_compat)) {
      STRACE_ERROR(gettimeofday, "Couldn't write timeval to memory");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (tz_addr) {
    linux32_timezone tz_compat = {
        .tz_minuteswest = tz.tz_minuteswest,
        .tz_dsttime = tz.tz_dsttime
    };
    if (!TryWriteMemory(memory, tz_addr, &tz_compat)) {
      STRACE_ERROR(gettimeofday, "Couldn't write timezone to memory");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(
      gettimeofday, "tv_sec=%ld, tv_usec=%ld, tz_minuteswest=%d, tz_dsttime=%d",
      tv.tv_sec, tv.tv_usec, tz.tz_minuteswest, tz.tz_dsttime);

  return syscall.SetReturn(memory, state, -ret);
}

// Emulate a 32-bit `settimeofday` system call.
static Memory *SysSetTimeOfDay32(Memory *memory, State *state,
                                 const SystemCallABI &syscall) {
  addr_t tv_addr = 0;
  addr_t tz_addr = 0;

  if (!syscall.TryGetArgs(memory, state, &tv_addr, &tz_addr)) {
    STRACE_ERROR(settimeofday, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct timeval tv = {};
  struct timezone tz = {};
  gettimeofday(&tv, &tz);

  if (tv_addr) {
    linux32_timeval tv_compat = {};
    if (!TryReadMemory(memory, tv_addr, &tv_compat)) {
      STRACE_ERROR(settimeofday, "Couldn't read timeval data.");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
    tv.tv_sec = static_cast<time_t>(tv_compat.tv_sec);
    tv.tv_usec = static_cast<suseconds_t>(tv_compat.tv_usec);
  }

  if (tz_addr) {
    linux32_timezone tz_compat = {};
    if (!TryReadMemory(memory, tz_addr, &tz_compat)) {
      STRACE_ERROR(settimeofday, "Couldn't read timezone data.");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
    tz.tz_minuteswest = tz_compat.tz_minuteswest;
    tz.tz_dsttime = tz_compat.tz_dsttime;
  }

  if (!settimeofday(&tv, &tz)) {
    STRACE_SUCCESS(settimeofday, "Set");
    return syscall.SetReturn(memory, state, 0);
  } else {
    auto err = errno;
    STRACE_ERROR(settimeofday, "%s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }
}

// Emulate a 32-bit `gettimeofday` system call.
static Memory *SysGetTimeOfDay(Memory *memory, State *state,
                               const SystemCallABI &syscall) {
  addr_t tv_addr = 0;
  addr_t tz_addr = 0;

  if (!syscall.TryGetArgs(memory, state, &tv_addr, &tz_addr)) {
    STRACE_ERROR(gettimeofday, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct timeval tv = {};
  struct timezone tz = {};
  gettimeofday(&tv, &tz);
  auto ret = errno;

  if (tv_addr) {
    if (!TryWriteMemory(memory, tv_addr, &tv)) {
      STRACE_ERROR(gettimeofday, "Couldn't write timeval to memory");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (tz_addr) {
    if (!TryWriteMemory(memory, tz_addr, &tz)) {
      STRACE_ERROR(gettimeofday, "Couldn't write timezone to memory");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(
      gettimeofday, "tv_sec=%ld, tv_usec=%ld, tz_minuteswest=%d, tz_dsttime=%d",
      tv.tv_sec, tv.tv_usec, tz.tz_minuteswest, tz.tz_dsttime);

  return syscall.SetReturn(memory, state, -ret);
}


}  // namespace
