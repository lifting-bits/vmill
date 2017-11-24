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

#ifdef VMILL_RUNTIME_X86

// Emulate the `set_thread_area` system calls.
template <typename T>
static Memory *SysSetThreadArea(Memory *memory, State *state,
                                const SystemCallABI &syscall) {
  addr_t addr = 0;
  if (!syscall.TryGetArgs(memory, state, &addr)) {
    STRACE_ERROR(set_thread_area, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

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

  STRACE_SUCCESS(set_thread_area,
                 "Set LDT entry number %u to base address %lx",
                 info.entry_number, info.base_addr);
  return syscall.SetReturn(memory, state, 0);
}

#endif  // VMILL_RUNTIME_X86

}  // namespace
