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

static linux_task *gTaskList = nullptr;
static linux_task *gLastTask = nullptr;

}  // namespace

static pid_t gNextTid = kProcessId;

// Initialize the emulated Linux operating system.
extern "C" void __vmill_init(void) {
//  printf("init\n");
  gNextTid = kProcessId;
  gTaskList = nullptr;
  gLastTask = nullptr;
}

// Tear down the emulated Linux operating system.
extern "C" void __vmill_fini(void) {
//  printf("fini\n");
  linux_task *next_task = nullptr;
  for (auto task = gTaskList; task; task = next_task) {
    next_task = task->next;
    task->next = nullptr;
    task->next_circular = nullptr;
    __vmill_fini_task(task);
    delete task;
//    printf("%p deleted\n", task);
  }

  gTaskList = nullptr;
  gLastTask = nullptr;
}

// Add a task to the operating system.
extern "C" linux_task *__vmill_create_task(
    const void *state, vmill::PC pc, vmill::AddressSpace *memory) {
  auto task = new linux_task;
  bzero(task, sizeof(linux_task));

  __vmill_init_task(task, state, pc, memory);

  task->tid = gNextTid++;

  if (gTaskList) {
    gLastTask->next_circular = task;
    task->next_circular = gTaskList;

  } else {
    gLastTask = task;
    task->next_circular = task;
  }

  task->next = gTaskList;
  gTaskList = task;

//  printf("%p new\n", task);

  return task;
}

// Call into vmill to execute the actual task.
extern "C" void __vmill_run(linux_task *task);

// Called by the executor when all initial tasks are loaded.
extern "C" void __vmill_resume(void) {
  for (auto progressed = true; progressed; ) {
    progressed = false;
    for (auto task = gTaskList; task; task = task->next) {
      switch (task->status) {
        case vmill::kTaskStatusRunnable:
        case vmill::kTaskStatusResumable:
          progressed = true;
          if (!task->blocked_count) {
//            printf("%p running \n", task);
            __vmill_run(task);
          } else {
//            printf("%p blocked: %u\n", task, task->blocked_count);
            task->blocked_count--;
          }
          break;

        default:
//          printf("%p Task status is %d\n", task, static_cast<int>(task->status));
          break;
      }
    }
  }
}

}  // namespace vmill

#endif  // TOOLS_VMILL_VMILL_RUNTIME_LINUX_LINUX_CPP_
