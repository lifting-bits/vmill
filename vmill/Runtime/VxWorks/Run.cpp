/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#ifndef VMILL_RUNTIME_VXWORKS_RUN_CPP_
#define VMILL_RUNTIME_VXWORKS_RUN_CPP_

namespace vmill {
namespace {
static Task *gTask = nullptr;
}

// Initialize the emulated Linux operating system.
extern "C" void __vmill_init(void) {

}

// Tear down the emulated Linux operating system.
extern "C" void __vmill_fini(void) {
  if (gTask) {
    __vmill_fini_task(gTask);
    delete gTask;
    gTask = nullptr;
  }
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

#endif  // VMILL_RUNTIME_VXWORKS_RUN_CPP_
