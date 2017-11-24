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

#ifndef FUTEX_PRIVATE_FLAG
# define FUTEX_PRIVATE_FLAG 128
#endif

enum FutexCommand {
  kFutexWait,
  kFutexWake,
  kFutedFd,
  kFutexRequeue,
  kFutexCompareAndRequeue,
  kFutexWakeOp,
  kFutexLockWithPriorityInheritance,
  kFutexUnlockWithPriorityInheritance,
  kFutexTryLockWithPriorityInheritance,
  kFutexWaitBitset,
  kFutexWakeBitset,
  kFutexWaitRequeueWithPriorityInheritance,
  kFutexCompareAndRequeueWithPriorityInheritance,
  kFutexInvalidCommand
};

FutexCommand FutexOpToCommand(int op) {
  if (0 > op) {
    return kFutexInvalidCommand;
  }
  op = op & 0x7F;

  if (op < static_cast<int>(kFutexInvalidCommand)) {
    return static_cast<FutexCommand>(op);
  } else {
    return kFutexInvalidCommand;
  }
}

const char *FutexCommandName(FutexCommand op) {
  switch (op) {
    case kFutexWait: return "FUTEX_WAIT";
    case kFutexWake: return "FUTEX_WAKE";
    case kFutedFd: return "FUTEX_FD";
    case kFutexRequeue: return "FUTEX_REQUEUE";
    case kFutexCompareAndRequeue: return "FUTEX_CMP_REQUEUE";
    case kFutexWakeOp: return "FUTEX_WAKE_OP";
    case kFutexLockWithPriorityInheritance: return "FUTEX_LOCK_PI";
    case kFutexUnlockWithPriorityInheritance: return "FUTEX_UNLOCK_PI";
    case kFutexTryLockWithPriorityInheritance: return "FUTEX_TRYLOCK_PI";
    case kFutexWaitBitset: return "FUTEX_WAIT_BITSET";
    case kFutexWakeBitset: return "FUTEX_WAKE_BITSET";
    case kFutexWaitRequeueWithPriorityInheritance:
      return "FUTEX_WAIT_REQUEUE_PI";
    case kFutexCompareAndRequeueWithPriorityInheritance:
      return "FUTEX_CMP_REQUEUE_PI";
    case kFutexInvalidCommand:
      return "<invalid>";
  }
}

static Memory *DoFutexWaitBitSet(Memory *memory, State *state,
                                 const SystemCallABI &syscall,
                                 addr_t uaddr, uint32_t val,
                                 struct timespec *timeout, uint32_t bitset) {

  if (0 != (uaddr % sizeof(uint32_t))) {
    STRACE_ERROR(futex_wait, "Unaligned uaddr=%" PRIxADDR, uaddr);
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if (!bitset) {
    STRACE_ERROR(futex_wait, "Empty bitset");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  uint32_t uval = 0;

  if (!TryReadMemory(memory, uaddr, &uval) ||
      !CanWriteMemory(memory, uaddr, sizeof(uval))) {
    STRACE_ERROR(futex_wait, "uaddr=%" PRIxADDR " must be readable and writable",
                 uaddr);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto task = __vmill_current();

  if (uval != val) {
    STRACE_SUCCESS(
        futex_wait, "Retry on uaddr=%" PRIxADDR " with val=%x and uval=%x",
        uaddr, val, uval);

    return syscall.SetReturn(memory, state, -EAGAIN);
  } else {

    if (task->futex_uaddr && !task->blocked_count) {
      assert(task->futex_uaddr == uaddr);
      task->futex_bitset = 0;
      task->futex_uaddr = 0;

      STRACE_SUCCESS(futex_wait, "Woken up");
      return syscall.SetReturn(memory, state, 0);
    }

    // TODO(pag): These numbers are made up and here to represent "rounds"
    //            through the executor that we're allowed to keep going for.
    if (task->blocked_count) {
      task->blocked_count--;
    } else if (timeout) {
      task->blocked_count = 100;
    } else {
      task->blocked_count = ~0U;  // Basically infinity.
    }

    if (!task->blocked_count) {
      task->futex_bitset = 0;
      task->futex_uaddr = 0;

      STRACE_SUCCESS(futex_wait, "Timed out on uaddr=%" PRIxADDR,
                     uaddr, val, uval);
      return syscall.SetReturn(memory, state, -ETIMEDOUT);

    } else {
      task->futex_bitset = bitset;
      task->futex_uaddr = uaddr;

      STRACE_SUCCESS(
          futex_wait, "Blocked on uaddr=%" PRIxADDR " with val=%x and uval=%x",
          uaddr, val, uval);

      // NOTE(pag): Leaves the syscall incomplete by not calling
      //            `syscall.SetReturn`.
      return memory;
    }
  }
}

static Memory *DoFutexWakeBitSet(Memory *memory, State *state,
                                 const SystemCallABI &syscall,
                                 addr_t uaddr, uint32_t num_to_wake,
                                 uint32_t bitset) {
  auto task = __vmill_current();
  task->blocked_count = 0;

  if (0 != (uaddr % sizeof(uint32_t))) {
    STRACE_ERROR(futex_wake, "Unaligned uaddr=%" PRIxADDR, uaddr);
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if (!bitset) {
    STRACE_ERROR(futex_wake, "Empty bitset");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if (!CanReadMemory(memory, uaddr, sizeof(uint32_t)) ||
      !CanWriteMemory(memory, uaddr, sizeof(uint32_t))) {
    STRACE_ERROR(
        futex_wake, "uaddr=%" PRIxADDR " must be readable and writable", uaddr);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  uint32_t num_woken = 0;

  for (auto next_task = task->next_circular;
       next_task != task;
       next_task = task->next_circular) {

    if (next_task->futex_uaddr == uaddr &&
        0 < next_task->blocked_count &&
        0U != (next_task->futex_bitset & bitset)) {

      next_task->blocked_count = 0;  // Unblock the task.

      num_woken++;
      if (num_woken >= num_to_wake) {
        break;
      }
    }
  }

  STRACE_SUCCESS(futex_wake, "Waking %u tasks blocked on uaddr=%" PRIxADDR,
                 num_woken, uaddr);
  return syscall.SetReturn(memory, state, num_woken);
}

// Emulate a `futex` system call.
//
// TODO(pag): Change this to emulate in terms of pthread-related function
//            calls (for portability to non-Linux platforms). Alternatively,
//            call out to a VMill scheduler of some kind.
template <typename TimeSpecT>
static Memory *SysFutex(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  addr_t uaddr = 0;
  int op = -1;
  uint32_t val = 0;
  uint32_t val2 = 0;
  addr_t utime = 0;
  addr_t uaddr2 = 0;
  uint32_t val3 = 0;

  if (!syscall.TryGetArgs(memory, state, &uaddr, &op, &val,
                          &utime, &uaddr2, &val3)) {
    STRACE_ERROR(futex, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto cmd = FutexOpToCommand(op);
  if (kFutexInvalidCommand == cmd) {
    STRACE_ERROR(futex, "Invalid command with op=%d", op);
    return syscall.SetReturn(memory, state, -ENOSYS);
  }

  // Read the timeout, or convert it to `val2`.
  struct timespec timeout = {};
  switch (cmd) {
    case kFutexWait:
    case kFutexLockWithPriorityInheritance:
    case kFutexWaitBitset:
    case kFutexWaitRequeueWithPriorityInheritance:
      if (utime) {
        TimeSpecT timeout_compat_val = {};
        if (!TryReadMemory(memory, utime, &timeout_compat_val)) {
          STRACE_ERROR(futex, "Fault reading utime=%" PRIxADDR, utime);
          return syscall.SetReturn(memory, state, -EFAULT);
        }

        timeout.tv_sec = static_cast<time_t>(timeout_compat_val.tv_sec);
        timeout.tv_nsec = static_cast<decltype(timeout.tv_nsec)>(
            timeout_compat_val.tv_nsec);
      }
      break;

    case kFutexRequeue:
    case kFutexCompareAndRequeue:
    case kFutexCompareAndRequeueWithPriorityInheritance:
    case kFutexWakeOp:
      val2 = static_cast<uint32_t>(utime);
      break;
    default:
      break;
  }

  // Validate the timeout.
  if (0 > timeout.tv_sec || timeout.tv_nsec > 1000000000L) {
    STRACE_ERROR(futex, "Invalid timeout with tv_sec=%ld and tv_nsec=%ld",
                 timeout.tv_sec, timeout.tv_nsec);
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  switch (cmd) {
    case kFutexWait:
      val3 = ~0U;
      [[clang::fallthrough]];
    case kFutexWaitBitset:
      return DoFutexWaitBitSet(
          memory, state, syscall, uaddr, val, &timeout, val3);

    case kFutexWake:
      val3 = ~0U;
      [[clang::fallthrough]];
    case kFutexWakeBitset:
      return DoFutexWakeBitSet(memory, state, syscall, uaddr, val, val3);

    case kFutexInvalidCommand:
      STRACE_ERROR(futex, "invalid futex command with op=%d", op);
      return syscall.SetReturn(memory, state, -EINVAL);

    default:
      STRACE_ERROR(futex, "unsupported futex command %s",
                   FutexCommandName(cmd));
      return syscall.SetReturn(memory, state, -ENOSYS);
  }
}

}  // namespace
