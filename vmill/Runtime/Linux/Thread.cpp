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

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#include <sched.h>

#ifdef __linux__
#include <asm/prctl.h>
#include <sys/prctl.h>
#endif

#ifndef __linux__
# define CLONE_VM 0x100
# define CLONE_FS 0x200
# define CLONE_FILES 0x400
# define CLONE_SIGHAND 0x800
# define CLONE_PTRACE 0x2000
# define CLONE_VFORK 0x4000
# define CLONE_PARENT 0x8000
# define CLONE_THREAD 0x10000
# define CLONE_NEWNS 0x20000
# define CLONE_SYSVSEM 0x40000
# define CLONE_SETTLS 0x80000
# define CLONE_PARENT_SETTID 0x100000
# define CLONE_CHILD_CLEARTID 0x200000
# define CLONE_DETACHED 0x400000
# define CLONE_UNTRACED 0x800000
# define CLONE_CHILD_SETTID 0x1000000
# define CLONE_NEWUTS 0x4000000
# define CLONE_NEWIPC 0x8000000
# define CLONE_NEWUSER 0x10000000
# define CLONE_NEWPID 0x20000000
# define CLONE_NEWNET 0x40000000
# define CLONE_IO 0x80000000

# define ARCH_SET_GS 0x1001
# define ARCH_SET_FS 0x1002
# define ARCH_GET_FS 0x1003
# define ARCH_GET_GS 0x1004
#endif

#ifndef CLONE_NEWCGROUP
# define CLONE_NEWCGROUP 0
#endif

#ifndef CLONE_PID
# define CLONE_PID 0
#endif

namespace {

#ifdef VMILL_RUNTIME_X86

// Emulate the `set_thread_area` system call.
template <typename T>
static Memory *DoSetThreadArea(Memory *memory, State *state,
                               const SystemCallABI &syscall,
                               addr_t addr) {
  T info = {};
  if (!TryReadMemory(memory, addr, &info)) {
    STRACE_ERROR(set_thread_area, "Couldn't read thread area info");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!info.IsEmpty() && !info.IsZero()) {

    if (!info.seg_32bit) {
      STRACE_ERROR(set_thread_area, "64-bit descriptor");
      return syscall.SetReturn(memory, state, -EINVAL);
    }

    if (info.contents != kSegContentsData &&
        info.contents != kSegContentsDataExpandDown) {
      STRACE_ERROR(set_thread_area, "Non-data segment");
      return syscall.SetReturn(memory, state, -EINVAL);
    }

    if (info.seg_not_present) {
      STRACE_ERROR(set_thread_area, "Non-present segment");
      return syscall.SetReturn(memory, state, -EINVAL);
    }
  }

  auto &index = info.entry_number;
  if (~0U != index) {
    if (index < kLinuxMinIndexForTLSInGDT ||
        kLinuxMaxIndexForTLSInGDT < index) {
      STRACE_ERROR(set_thread_area, "Invalid LDT TLS index.");
      return syscall.SetReturn(memory, state, -EINVAL);
    }

  // See: https://code.woboq.org/linux/linux/arch/x86/include/asm/segment.h.html#_M/GDT_ENTRY_TLS_MIN
  } else {
    auto found = false;
    for (index = kLinuxMinIndexForTLSInGDT;
         index <= kLinuxMaxIndexForTLSInGDT;
         ++index) {

      if (state->seg.fs.index != index &&
          state->seg.gs.index != index) {
        found = true;
        break;
      }
    }

    if (!found) {
      STRACE_ERROR(set_thread_area, "Could not find unused LDT TLS index.");
      return syscall.SetReturn(memory, state, -ESRCH);
    }

    addr_t entry_addr = addr + __builtin_offsetof(T, entry_number);
    if (!TryWriteMemory(memory, entry_addr, index)) {
      STRACE_ERROR(set_thread_area, "Can't write back index.");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  // Make sure any other segments with this index have their corresponding
  // base addresses updated to reflect the new LDT entry.

  if (state->seg.ss.index == index) {
    state->addr.ss_base.dword = info.base_addr;
  }

  if (state->seg.es.index == index) {
    state->addr.es_base.dword = info.base_addr;
  }

  if (state->seg.gs.index == index) {
    state->addr.gs_base.dword = info.base_addr;
  }

  if (state->seg.fs.index == index) {
    state->addr.fs_base.dword = info.base_addr;
  }

  if (state->seg.ds.index == index) {
    state->addr.ds_base.dword = info.base_addr;
  }

  if (state->seg.cs.index == index) {
    state->addr.cs_base.dword = info.base_addr;
  }

  auto task = __vmill_current();
  task->tls_slots[index - kLinuxMinIndexForTLSInGDT] = info;

  STRACE_SUCCESS(
      set_thread_area,
      "Set LDT entry number %" PRIu32 " to base address %" PRIx32,
      info.entry_number, info.base_addr);
  return syscall.SetReturn(memory, state, 0);
}

// Emulate the `set_thread_area` system call.
template <typename T>
static Memory *SysSetThreadArea(Memory *memory, State *state,
                                const SystemCallABI &syscall) {
  addr_t addr = 0;
  if (!syscall.TryGetArgs(memory, state, &addr)) {
    STRACE_ERROR(set_thread_area, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  return DoSetThreadArea<T>(memory, state, syscall, addr);
}

#endif  // VMILL_RUNTIME_X86

// Emulate the `clone` system call.
static Memory *DoClone(Memory *memory, State *state,
                       const SystemCallABI &syscall, addr_t child_stack,
                       addr_t flags, addr_t ptid, addr_t newtls, addr_t ctid) {

  addr_t thread_flags = CLONE_FILES | CLONE_FS | CLONE_IO |
                        CLONE_PID | CLONE_VM;

  addr_t not_thread_flags = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET |
                            CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER |
                            CLONE_NEWUTS | CLONE_PARENT;

  // TODO(pag): `CLONE_THREAD` is quite complex so we'll ignore it for now.

  if (thread_flags != (thread_flags & flags) &&
      0 != (flags & not_thread_flags)) {
    STRACE_ERROR(clone, "Trying to create a process?");
    __vmill_set_location(0, vmill::kTaskStoppedAtExit);
    return memory;
  }

  if ((CLONE_THREAD & flags) && !(CLONE_SIGHAND & flags)) {
    STRACE_ERROR(clone, "Thread groups need to change signal handlers.");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if ((CLONE_SIGHAND & flags) && !(CLONE_VM & flags)) {
    STRACE_ERROR(clone, "Signal handlers exist must exist in the same memory.");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if (CLONE_PARENT_SETTID & flags) {
    if (!CanWriteMemory(memory, ptid, sizeof(pid_t))) {
      STRACE_ERROR(clone, "Can't write tid to parent ptid=%" PRIxADDR, ptid);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (CLONE_CHILD_SETTID & flags) {
    if (!CanWriteMemory(memory, ctid, sizeof(pid_t))) {
      STRACE_ERROR(clone, "Can't write tid to child ctid=%" PRIxADDR, ctid);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  // Get the return address of this system call, which is the resume point for
  // the child thread.
  addr_t ret_addr = syscall.GetReturnAddress(
      memory, state, syscall.GetPC(state));

  linux_task *parent = __vmill_current();
  linux_task *child = __vmill_create_task(
      parent->state, static_cast<vmill::PC>(ret_addr), parent->memory);

  child->last_pc = parent->last_pc;
  auto child_state = reinterpret_cast<State *>(child->state);

  // Make it so that the child resumes where the parent left off.
  syscall.SetPC(child_state, ret_addr);

  // Set up the child stack.
  if (child_stack) {
    syscall.SetSP(child_state, child_stack);
  }

  child->status = vmill::kTaskStatusRunnable;
  child->location = vmill::kTaskStoppedAfterHyperCall;

  if (CLONE_PARENT_SETTID & flags) {
    (void) TryWriteMemory(memory, ptid, child->tid);
  }

  if (CLONE_CHILD_SETTID & flags) {
    (void) TryWriteMemory(memory, ctid, child->tid);
    child->set_child_tid = ctid;
  }

  if (CLONE_CHILD_CLEARTID & flags) {
    child->clear_child_tid = ctid;
  }

  STRACE_SUCCESS(
      clone, "flags=%" PRIxADDR ", ptid=%" PRIxADDR ", ctid=%" PRIxADDR
      ", child pc=%" PRIxADDR ", child sp=%" PRIxADDR ", child tid=%" PRId32,
      flags, ptid, ctid, ret_addr, child_stack, child->tid);

  // Set the return for the child.
  memory = syscall.SetReturn(memory, child_state, 0);

  // Set the return for the parent.
  memory = syscall.SetReturn(memory, state, child->tid);

  if (CLONE_SETTLS & flags) {
#if defined(VMILL_RUNTIME_X86)
# if 32 == VMILL_RUNTIME_X86
    memory = DoSetThreadArea<linux_x86_user_desc>(
        memory, child_state, syscall, newtls);
# else
    child_state->addr.fs_base.aword = newtls;
# endif
#elif defined(VMILL_RUNTIME_AARCH64)
    child_state->sr.tpidr_el0.aword = newtls;
#else
# error "Unsupported architecture!"
#endif
  }

  return memory;
}

// Emulate the `clone` system call on x86-64.
static Memory *SysCloneA(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  addr_t child_stack = 0;
  addr_t flags = 0;
  addr_t ptid = 0;
  addr_t newtls = 0;
  addr_t ctid = 0;

  if (!syscall.TryGetArgs(memory, state, &flags, &child_stack,
                          &ptid, &ctid, &newtls)) {
    STRACE_ERROR(clone, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  return DoClone(memory, state, syscall, child_stack,
                 flags, ptid, newtls, ctid);
}


// Emulate the `clone` system call on x86, ARMv8.
static Memory *SysCloneB(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  addr_t child_stack = 0;
  addr_t flags = 0;
  addr_t ptid = 0;
  addr_t newtls = 0;
  addr_t ctid = 0;

  if (!syscall.TryGetArgs(memory, state, &flags, &child_stack,
                          &ptid, &newtls, &ctid)) {
    STRACE_ERROR(set_thread_area, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  return DoClone(memory, state, syscall, child_stack,
                 flags, ptid, newtls, ctid);
}

#if 64 == VMILL_RUNTIME_X86
// Emulate the `arch_prctl` system call on x86, ARMv8.
static Memory *SysArchPrctl(Memory *memory, State *state,
                            const SystemCallABI &syscall) {
  int code = 0;
  addr_t addr = 0;
  if (!syscall.TryGetArgs(memory, state, &code, &addr)) {
    STRACE_ERROR(arch_prctl, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  switch (code) {
    case ARCH_SET_FS:
      if (!__vmill_can_read_byte(memory, addr)) {
        STRACE_ERROR(
            arch_prctl, "Invalid addr=%" PRIxADDR " for ARCH_SET_FS", addr);
        return syscall.SetReturn(memory, state, -EPERM);
      } else {
        state->addr.fs_base.aword = addr;
        STRACE_SUCCESS(arch_prctl, "Set FS base to addr=%" PRIxADDR, addr);
        return syscall.SetReturn(memory, state, 0);
      }

    case ARCH_SET_GS:
      if (!__vmill_can_read_byte(memory, addr)) {
        STRACE_ERROR(
            arch_prctl, "Invalid addr=%" PRIxADDR " for ARCH_SET_GS", addr);
        return syscall.SetReturn(memory, state, -EPERM);
      } else {
        state->addr.gs_base.aword = addr;
        STRACE_SUCCESS(arch_prctl, "Set GS base to addr=%" PRIxADDR, addr);
        return syscall.SetReturn(memory, state, 0);
      }

    case ARCH_GET_FS:
      if (!TryWriteMemory(memory, addr, state->addr.fs_base.aword)) {
        STRACE_ERROR(
            arch_prctl, "Can't write FS base to addr=%" PRIxADDR, addr);
        return syscall.SetReturn(memory, state, -EFAULT);
      } else {
        STRACE_SUCCESS(
            arch_prctl, "Set FS base to [addr=%" PRIxADDR "]=%" PRIxADDR,
            addr, state->addr.fs_base.aword);
        return syscall.SetReturn(memory, state, 0);
      }

    case ARCH_GET_GS:
      if (!TryWriteMemory(memory, addr, state->addr.gs_base.aword)) {
        STRACE_ERROR(
            arch_prctl, "Can't write GS base to addr=%" PRIxADDR, addr);
        return syscall.SetReturn(memory, state, -EFAULT);
      } else {
        STRACE_SUCCESS(
            arch_prctl, "Set GS base to [addr=%" PRIxADDR "]=%" PRIxADDR,
            addr, state->addr.gs_base.aword);
        return syscall.SetReturn(memory, state, 0);
      }

    default:
      STRACE_ERROR(arch_prctl, "Invalid code=%d", code);
      return syscall.SetReturn(memory, state, -EINVAL);
  }
}
#endif  // 64 == VMILL_RUNTIME_X86

// Emulate the `set_tid_address` system call.
static Memory *SysSetThreadIdAddress(Memory *memory, State *state,
                                     const SystemCallABI &syscall) {
  addr_t tidptr = 0;
  if (!syscall.TryGetArgs(memory, state, &tidptr)) {
    STRACE_ERROR(set_tid_address, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto task = __vmill_current();
  task->clear_child_tid = tidptr;
  STRACE_SUCCESS(set_tid_address, "clear_child_tid=%" PRIxADDR, tidptr);
  return syscall.SetReturn(memory, state, task->tid);
}

}  // namespace
