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
    case kFutexWait:
      return "FUTEX_WAIT";
    case kFutexWake:
      return "FUTEX_WAKE";
    case kFutedFd:
      return "FUTEX_FD";
    case kFutexRequeue:
      return "FUTEX_REQUEUE";
    case kFutexCompareAndRequeue:
      return "FUTEX_CMP_REQUEUE";
    case kFutexWakeOp:
      return "FUTEX_WAKE_OP";
    case kFutexLockWithPriorityInheritance:
      return "FUTEX_LOCK_PI";
    case kFutexUnlockWithPriorityInheritance:
      return "FUTEX_UNLOCK_PI";
    case kFutexTryLockWithPriorityInheritance:
      return "FUTEX_TRYLOCK_PI";
    case kFutexWaitBitset:
      return "FUTEX_WAIT_BITSET";
    case kFutexWakeBitset:
      return "FUTEX_WAKE_BITSET";
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

  auto task = __vmill_current();

  while (true) {
    if (!TryReadMemory(memory, uaddr, &uval) ||
        !CanWriteMemory(memory, uaddr, sizeof(uval))) {
      STRACE_ERROR(
          futex_wait, "uaddr=%" PRIxADDR " must be readable and writable",
          uaddr);
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    if (uval != val) {
      task->futex_uaddr = 0;
      task->blocked_count = 0;

      STRACE_SUCCESS(
          futex_wait, "Retry on uaddr=%" PRIxADDR " with val=%x and uval=%x",
          uaddr, val, uval);

      return syscall.SetReturn(memory, state, -EAGAIN);
    } else {

      if (task->futex_uaddr && !task->blocked_count) {
        assert(task->futex_uaddr == uaddr);
        task->futex_bitset = 0;
        task->futex_uaddr = 0;

        STRACE_SUCCESS(futex_wait, "Woken up on val=%x and uaddr=%" PRIxADDR,
                       val, uaddr);
        return syscall.SetReturn(memory, state, 0);
      }

      // TODO(pag): These numbers are made up and here to represent "rounds"
      //            through the executor that we're allowed to keep going for.
      if (task->blocked_count) {
        task->blocked_count--;
      } else if (timeout) {
        task->blocked_count = kFutexBlockedForABit;
      } else {
        task->blocked_count = kBlockedForever;
      }

      if (!task->blocked_count) {
        task->futex_bitset = 0;
        task->futex_uaddr = 0;

        STRACE_SUCCESS(futex_wait, "Timed out on uaddr=%" PRIxADDR, uaddr);
        return syscall.SetReturn(memory, state, -ETIMEDOUT);

      } else {
        task->futex_bitset = bitset;
        task->futex_uaddr = uaddr;

        STRACE_SUCCESS(
            futex_wait,
            "Blocked on uaddr=%" PRIxADDR " with val=%x and uval=%x",
            uaddr, val, uval);

        __vmill_yield(task);
      }
    }
  }
}

static uint32_t DoWake(linux_task *task, addr_t uaddr, uint32_t bitset,
                       uint32_t num_to_wake) {
  uint32_t num_woken = 0;
  for (auto next_task = task->next_circular;
       next_task != task;
       next_task = next_task->next_circular) {

    // Tasks in different address spaces can't share futexes (in vmill).
    if (task->memory != next_task->memory) {
      continue;
    }

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
  return num_woken;
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

  auto num_woken = DoWake(task, uaddr, bitset, num_to_wake);

  STRACE_SUCCESS(futex_wake, "Waking %u tasks blocked on uaddr=%" PRIxADDR,
                 num_woken, uaddr);
  return syscall.SetReturn(memory, state, num_woken);
}

enum FutexOperator : uint32_t {
  kFutexOperatorSet,
  kFutexOperatorAdd,
  kFutexOperatorOr,
  kFutexOperatorAndNot,
  kFutexOperatorXor
};

enum FutexComparator : uint32_t {
  kFutexCompareEqual,
  kFutexCompareNotEqual,
  kFutexCompareLessThan,
  kFutexCompareLessThanEqual,
  kFutexCompareGreaterThan,
  kFutexCompareGreaterThanEqual
};

union FutexOp {
  uint32_t flat;
  struct {
    int32_t cmparg:12;
    int32_t oparg:12;
    uint32_t cmp:4;
    uint32_t op:4;
  } __attribute__((packed));
} __attribute__((packed));

static constexpr uint32_t kFutexShiftOpArg = 8;

static_assert(sizeof(FutexOp) == sizeof(uint32_t),
              "Invalid packing of `union FutexOpArg`.");

//      8 futex_wake_op(u32 __user *uaddr1, unsigned int flags, u32 __user *uaddr2,
//      1609          int nr_wake, int nr_wake2, int op)

static Memory *DoFutexWakeOp(Memory *memory, State *state,
                             const SystemCallABI &syscall,
                             addr_t uaddr1, unsigned flags,
                             addr_t uaddr2, uint32_t num_to_wake1,
                             uint32_t num_to_wake2, uint32_t op_) {
  FutexOp op = {op_};

  // Get the `oparg`. We may need to shift it.
  int32_t oparg = op.oparg;
  if (op.op & kFutexShiftOpArg) {
    if (oparg > 0 || 31 < oparg) {
      STRACE_ERROR(futex_wake_op, "oparg=%d is out of bounds for shift", oparg);
      return syscall.SetReturn(memory, state, -EINVAL);
    }

    op.op ^= kFutexShiftOpArg;
    oparg = 1 << oparg;
  }

  if (op.op > static_cast<uint32_t>(kFutexOperatorXor)) {
    STRACE_ERROR(futex_wake_op, "op=%u is out of bounds", op.op);
    return syscall.SetReturn(memory, state, -ENOSYS);
  }

  if (op.cmp > static_cast<uint32_t>(kFutexCompareGreaterThanEqual)) {
    STRACE_ERROR(futex_wake_op, "cmp=%u is out of bounds", op.cmp);
    return syscall.SetReturn(memory, state, -ENOSYS);
  }

  int32_t old_val = 0;
  if (!TryReadMemory(memory, uaddr2, &old_val)) {
    STRACE_ERROR(futex_wake, "Could read oldval from uaddr2=%" PRIxADDR,
                 uaddr2);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!CanWriteMemory(memory, uaddr2, sizeof(old_val))) {
    STRACE_ERROR(futex_wake, "Can't write new val back to uaddr2=%" PRIxADDR,
                 uaddr2);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  int32_t new_val = 0;
  switch (static_cast<FutexOperator>(op.op)) {
    case kFutexOperatorSet:
      new_val = oparg;
      break;
    case kFutexOperatorAdd:
      new_val = old_val + oparg;
      break;
    case kFutexOperatorOr:
      new_val = old_val | oparg;
      break;
    case kFutexOperatorAndNot:
      new_val = old_val & ~oparg;
      break;
    case kFutexOperatorXor:
      new_val = old_val ^ oparg;
      break;
  }

  (void) TryWriteMemory(memory, uaddr2, new_val);

  bool wake_another = false;
  const auto cmparg = op.cmparg;
  switch (static_cast<FutexComparator>(op.cmp)) {
    case kFutexCompareEqual:
      wake_another = old_val == cmparg;
      break;
    case kFutexCompareNotEqual:
      wake_another = old_val != cmparg;
      break;
    case kFutexCompareLessThan:
      wake_another = old_val < cmparg;
      break;
    case kFutexCompareLessThanEqual:
      wake_another = old_val <= cmparg;
      break;
    case kFutexCompareGreaterThan:
      wake_another = old_val > cmparg;
      break;
    case kFutexCompareGreaterThanEqual:
      wake_another = old_val >= cmparg;
      break;
  }

  auto task = __vmill_current();
  auto num_woken1 = DoWake(task, uaddr1, ~0U, num_to_wake1);
  uint32_t num_woken2 = 0;
  if (wake_another) {
    num_woken2 += DoWake(task, uaddr2, ~0U, num_to_wake2);
  }

  STRACE_SUCCESS(
      futex_wake_op, "Waking %u tasks blocked on uaddr1=%" PRIxADDR
      " and %u tasks blocks on uaddr2=%" PRIxADDR,
      num_woken1, uaddr1, num_woken2, uaddr2);
  return syscall.SetReturn(memory, state, num_woken1 + num_woken2);
}

// Emulate a `futex` system call.
template <typename TimeSpecT>
static Memory *SysFutex(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  addr_t uaddr = 0;
  int op = -1;
  unsigned flags = 0;
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

    case kFutexWakeOp:
      return DoFutexWakeOp(memory, state, syscall, uaddr,
                           flags, uaddr2, val, val2, val3);

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
