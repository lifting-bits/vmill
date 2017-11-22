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

  if (info.IsEmpty() || info.IsZero()) {
    STRACE_ERROR(set_thread_area, "Empty or zero descriptor");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

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

  auto &index = info.entry_number;
  if (~0U != index) {
    if (index < 12 || 14 < index) {
      STRACE_ERROR(set_thread_area, "Invalid index.");
      return syscall.SetReturn(memory, state, -EINVAL);
    }

  // See: https://code.woboq.org/linux/linux/arch/x86/include/asm/segment.h.html#_M/GDT_ENTRY_TLS_MIN
  } else {
    uint32_t choices[] = {12, 13, 14};
    auto found = false;
    for (auto &choice : choices) {
      if (state->seg.fs.index != choice &&
          state->seg.gs.index != choice) {
        index = choice;
        found = true;
        break;
      }
    }

    if (!found) {
      STRACE_ERROR(set_thread_area, "Could not find untaken index.");
      return syscall.SetReturn(memory, state, -ESRCH);
    }

    addr_t entry_addr = addr + __builtin_offsetof(T, entry_number);
    if (!TryWriteMemory(memory, entry_addr, index)) {
      STRACE_ERROR(set_thread_area, "Can't write back index.");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

#if 32 == VMILL_RUNTIME_X86
  auto &seg_sel = state->seg.gs;
  auto &seg_base = state->addr.gs_base;
#else
  auto &seg_sel = state->seg.fs;
  auto &seg_base = state->addr.fs_base;
#endif

  seg_sel.index = static_cast<uint16_t>(index);
  seg_sel.rpi = kRingThree;
  seg_sel.ti = kGlobalDescriptorTable;
  seg_base.aword = static_cast<addr_t>(info.base_addr);

  STRACE_SUCCESS(set_thread_area, "Set LDT index %u to base address %lx",
                 index, info.base_addr);
  return syscall.SetReturn(memory, state, 0);
}

#endif  // VMILL_RUNTIME_X86

}  // namespace
