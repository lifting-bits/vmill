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
#ifndef VMILL_BC_COMPILER_H_
#define VMILL_BC_COMPILER_H_

#include <memory>

#include <llvm/Target/TargetOptions.h>

namespace llvm {
class LLVMContext;
class MemoryBuffer;
class Module;
class TargetMachine;
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill
namespace vmill {

// Compiles LLVM bitcode modules into LLVM object files.
class Compiler {
 public:
  virtual ~Compiler(void);

  explicit Compiler(
      const std::shared_ptr<llvm::LLVMContext> &context_);

  void CompileModuleToFile(
      llvm::Module &module, const std::string &path);

 private:
  Compiler(void) = delete;

  // LLVM Context associated with all modules to be compiled.
  std::shared_ptr<llvm::LLVMContext> context;

  // The host architecture on which we're running.
  const remill::Arch * const host_arch;

  // Compilation target options. This affects things like optimizations.
  llvm::TargetOptions options;

  // The target machine (i.e. the host machine).
  std::unique_ptr<llvm::TargetMachine> machine;
};

}  // namespace vmill

#endif  // VMILL_BC_COMPILER_H_
