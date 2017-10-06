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

#ifndef VMILL_BC_EXECUTOR_H_
#define VMILL_BC_EXECUTOR_H_

#include <memory>
#include <string>

namespace llvm {
class LLVMContext;
class Module;
}  // namespace llvm
namespace vmill {

struct Task;
struct LiftedTrace;

class Executor {
 public:
  virtual ~Executor(void);

  static Executor *GetNativeExecutor(
      const std::shared_ptr<llvm::LLVMContext> &context_);

  // Call into the runtime to allocate a `State` structure, and fill it with
  // the bytes from `data`.
  virtual void *AllocateStateInRuntime(const std::string &data) = 0;

  // Execute some code associated with a task.
  virtual void Execute(const Task &task, llvm::Function *func) = 0;

 protected:
  explicit Executor(const std::shared_ptr<llvm::LLVMContext> &context_);

  std::shared_ptr<llvm::LLVMContext> context;

 private:
  Executor(void) = delete;
};

}  // namespace vmill

#endif  // VMILL_BC_EXECUTOR_H_
