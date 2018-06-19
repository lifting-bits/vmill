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

#define ADDRESS_SIZE_BITS 32
#define HAS_FEATURE_AVX 0
#define HAS_FEATE_AVX512 0
#define VMILL_RUNTIME_X86 32
#define VMILL_RUNTIME

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cfenv>
#include <cfloat>
#include <cinttypes>
#include <climits>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-alignof-expression"

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/X86/Runtime/State.h"

#include "vmill/Runtime/Generic/Intrinsics.h"
#include "vmill/Runtime/Generic/Memory.cpp"
#include "vmill/Runtime/Generic/X86.cpp"
#include "vmill/Runtime/Generic/Run.cpp"

#pragma clang diagnostic pop

extern "C" {
int main(int argc, char **argv, char **envp);
void qemu_shutdown(void);
}  // extern C

namespace vmill {
namespace {
static Task *gTask = nullptr;
}

// Initialize the emulated Linux operating system.
extern "C" void __vmill_init(void) {
  const char *argv[] = {
      "qemu-system-i386",
      "-net",
      "nic,macaddr=0:0:e8:1:2:3,model=i82551",
      "-drive",
      "if=floppy,format=raw,file=/home/pag/shared/ReadStdin/floppy.i386.img",
      "--cpu",
      "pentium3",
      "-serial",
      "stdio",
      "-enable-kvm",
      nullptr
  };
  char *envp[] = {nullptr};
  main(10, const_cast<char **>(argv), envp);
}

// Tear down the emulated Linux operating system.
extern "C" void __vmill_fini(void) {
  if (gTask) {
    __vmill_fini_task(gTask);
    delete gTask;
    gTask = nullptr;
  }
  qemu_shutdown();
}

// Add a task to the operating system.
extern "C" Task *__vmill_create_task(
    const void *state, vmill::PC pc, vmill::AddressSpace *memory) {
  gTask = new Task;
  bzero(gTask, sizeof(*gTask));
  __vmill_init_task(gTask, state, pc, memory);
  return gTask;
}

// Call into vmill to execute the actual task.
extern "C" void __vmill_run(Task *task);

// Called by the executor when all initial tasks are loaded.
extern "C" void __vmill_resume(void) {
  for (auto progressed = true; progressed; ) {
    progressed = false;
    switch (gTask->status) {
      case vmill::kTaskStatusRunnable:
      case vmill::kTaskStatusResumable:
        progressed = true;
        __vmill_run(gTask);
        break;

      default:
        printf("Task status %p = %" PRIx64 "\n",
               reinterpret_cast<void *>(&(gTask->status)), gTask->status);
        break;
    }
  }
}

}  // namespace vmill
