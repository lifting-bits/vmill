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
#ifndef VMILL_WORKSPACE_WORKSPACE_H_
#define VMILL_WORKSPACE_WORKSPACE_H_

#include <string>

namespace vmill {
class Executor;
class ProgramSnapshotPtr;

class Workspace {
 public:
  static const std::string &Dir(void);
  static const std::string &SnapshotPath(void);
  static const std::string &MemoryDir(void);
  static const std::string &BitcodeDir(void);
  static const std::string &ToolDir(void);
  static const std::string &LibraryDir(void);
  static const std::string &RuntimeBitcodePath(void);
  static const std::string &RuntimeLibraryPath(void);

  static void LoadSnapshotIntoExecutor(
      const ProgramSnapshotPtr &snapshot, Executor &executor);

 private:
  Workspace(void) = delete;
};

}  // namespace vmill

#endif  // VMILL_WORKSPACE_WORKSPACE_H_
