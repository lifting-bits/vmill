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

#ifndef VMILL_RUNTIME_TASKSTATUS_H_
#define VMILL_RUNTIME_TASKSTATUS_H_

namespace vmill {

enum TaskStatus {
  kTaskStoppedAtSnapshotEntryPoint,
  kTaskStoppedAtJumpTarget,
  kTaskStoppedAtCallTarget,
  kTaskStoppedAtReturnTarget,
  kTaskStoppedAtError,
  kTaskStoppedAfterHyperCall,
  kTaskStoppedBeforeUnhandledHyperCall
};

}  // namespace vmill

#endif  // VMILL_RUNTIME_TASKSTATUS_H_
