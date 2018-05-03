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

#ifndef VMILL_RUNTIME_VXWORKS_RUN_H_
#define VMILL_RUNTIME_VXWORKS_RUN_H_

#include "vmill/Runtime/Task.h"

#if 32 == ADDRESS_SIZE_BITS
# define PRIdADDR PRId32
# define PRIxADDR PRIx32
# define PRIuADDR PRIu32
#else
# define PRIdADDR PRId64
# define PRIxADDR PRIx64
# define PRIuADDR PRIu64
#endif

// Returns a pointer to the currently executing task.
extern "C" vmill::Task *__vmill_current(void);

// Add a task to the operating system.
extern "C" vmill::Task *__vmill_create_task(
    const void *state, vmill::PC pc, vmill::AddressSpace *memory);


#endif  // VMILL_RUNTIME_VXWORKS_RUN_H_
