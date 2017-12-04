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
template <typename TimeVal, typename TimeZone>
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
  auto ret = gettimeofday(&tv, &tz);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(gettimeofday, "%s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  if (tv_addr) {
    TimeVal tv_compat = {};
    tv_compat.tv_sec = static_cast<decltype(tv_compat.tv_sec)>(tv.tv_sec);
    tv_compat.tv_usec = static_cast<decltype(tv_compat.tv_usec)>(tv.tv_usec);

    if (!TryWriteMemory(memory, tv_addr, &tv_compat)) {
      STRACE_ERROR(gettimeofday, "Couldn't write timeval to memory");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (tz_addr) {
    TimeZone tz_compat = {};
    tz_compat.tz_minuteswest = static_cast<decltype(tz_compat.tz_minuteswest)>(
        tz.tz_minuteswest);
    tz_compat.tz_dsttime = static_cast<decltype(tz_compat.tz_dsttime)>(
        tz.tz_dsttime);

    if (!TryWriteMemory(memory, tz_addr, &tz_compat)) {
      STRACE_ERROR(gettimeofday, "Couldn't write timezone to memory");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(
      gettimeofday, "tv_sec=%ld, tv_usec=%ld, tz_minuteswest=%d, tz_dsttime=%d",
      tv.tv_sec, tv.tv_usec, tz.tz_minuteswest, tz.tz_dsttime);

  return syscall.SetReturn(memory, state, ret);
}

// Emulate a 32-bit `settimeofday` system call.
template <typename TimeVal, typename TimeZone>
static Memory *SysSetTimeOfDay(Memory *memory, State *state,
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
    TimeVal tv_compat = {};
    if (!TryReadMemory(memory, tv_addr, &tv_compat)) {
      STRACE_ERROR(settimeofday, "Couldn't read timeval data.");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(tv_compat.tv_sec);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>(tv_compat.tv_usec);
  }

  if (tz_addr) {
    TimeZone tz_compat = {};
    if (!TryReadMemory(memory, tz_addr, &tz_compat)) {
      STRACE_ERROR(settimeofday, "Couldn't read timezone data.");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
    tz.tz_minuteswest = static_cast<decltype(tz.tz_minuteswest)>(
        tz_compat.tz_minuteswest);
    tz.tz_dsttime = static_cast<decltype(tz.tz_dsttime)>(
        tz_compat.tz_dsttime);
  }

  if (!settimeofday(tv_addr ? &tv : nullptr, tz_addr ? &tz : nullptr)) {
    STRACE_SUCCESS(
        settimeofday,
        "set tv_sec=%ld, tv_usec=%ld, tz_minuteswest=%d, tz_dsttime=%d",
        tv.tv_sec, tv.tv_usec, tz.tz_minuteswest, tz.tz_dsttime);
    return syscall.SetReturn(memory, state, 0);
  } else {
    auto err = errno;
    STRACE_ERROR(settimeofday, "%s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }
}

template <typename TimeSpec>
static Memory *SysClockGetTime(Memory *memory, State *state,
                               const SystemCallABI &syscall) {
  clockid_t clock_id = 0;
  addr_t tp = 0;

  if (!syscall.TryGetArgs(memory, state, &clock_id, &tp)) {
    STRACE_ERROR(clock_gettime, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct timespec cur_time = {};
  auto ret = clock_gettime(clock_id, &cur_time);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(clock_gettime, "Couldn't get time: %s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  TimeSpec compat_time = {};
  compat_time.tv_sec = static_cast<decltype(compat_time.tv_sec)>(
      cur_time.tv_sec);
  compat_time.tv_nsec = static_cast<decltype(compat_time.tv_nsec)>(
      cur_time.tv_nsec);

  if (!TryWriteMemory(memory, tp, compat_time)) {
    STRACE_ERROR(clock_gettime, "Couldn't write tp=%" PRIxADDR, tp);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  STRACE_SUCCESS(clock_gettime, "tv_sec=%ld, tv_nsec=%ld",
                 cur_time.tv_sec, cur_time.tv_nsec);
  return syscall.SetReturn(memory, state, 0);
}


template <typename TimeSpec>
static Memory *SysClockGetResolution(Memory *memory, State *state,
                                     const SystemCallABI &syscall) {
  clockid_t clock_id = 0;
  addr_t res = 0;

  if (!syscall.TryGetArgs(memory, state, &clock_id, &res)) {
    STRACE_ERROR(clock_getres, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct timespec cur_res = {};
  auto ret = clock_getres(clock_id, &cur_res);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(
        clock_getres, "Couldn't get resolution for clock_id=%d: %s",
        clock_id, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  TimeSpec compat_res = {};
  compat_res.tv_sec = static_cast<decltype(compat_res.tv_sec)>(
      cur_res.tv_sec);
  compat_res.tv_nsec = static_cast<decltype(compat_res.tv_nsec)>(
      cur_res.tv_nsec);

  if (!TryWriteMemory(memory, res, compat_res)) {
    STRACE_ERROR(clock_getres, "Couldn't write to res=%" PRIxADDR, res);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  STRACE_SUCCESS(clock_getres, "clock_id=%d, tv_sec=%ld, tv_nsec=%ld",
                 clock_id, cur_res.tv_sec, cur_res.tv_nsec);
  return syscall.SetReturn(memory, state, 0);
}

}  // namespace
