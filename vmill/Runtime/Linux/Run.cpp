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

#ifndef TOOLS_VMILL_VMILL_RUNTIME_LINUX_LINUX_CPP_
#define TOOLS_VMILL_VMILL_RUNTIME_LINUX_LINUX_CPP_

namespace vmill {
namespace {

struct LinuxTask : public Task {
  LinuxTask *next;
  LinuxTask **link;
};

static LinuxTask *gTaskList = nullptr;

}  // namespace

// Initialize the emulated Linux operating system.
extern "C" void __vmill_init(void) {

}

// Tear down the emulated Linux operating system.
extern "C" void __vmill_fini(void) {

}

// Add a task to the operating system.
extern "C" void __vmill_create_task(
    const void *state, vmill::PC pc, vmill::AddressSpace *memory) {
  auto task = new LinuxTask;
  memset(task, 0, sizeof(LinuxTask));
  __vmill_init_task(task, state, pc, memory);

  if (gTaskList) {
    gTaskList->link = &(task->next);
  }

  task->next = gTaskList;
  task->link = &gTaskList;
  gTaskList = task;
}

// Call into vmill to execute the actual task.
extern "C" void __vmill_run(vmill::Task *task);

// Called by the executor when all initial tasks are loaded.
extern "C" void __vmill_resume(void) {
  for (auto progressed = true; progressed; ) {
    progressed = false;
    for (auto task = gTaskList; task; task = task->next) {
      switch (task->status) {
        case vmill::kTaskStatusRunnable:
          progressed = true;
          __vmill_run(task);
          break;

        default:
          break;
      }
    }
  }
}

}  // namespace vmill

#endif  // TOOLS_VMILL_VMILL_RUNTIME_LINUX_LINUX_CPP_
