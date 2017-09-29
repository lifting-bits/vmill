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
#ifndef VMILL_BC_RUNTIME_H_
#define VMILL_BC_RUNTIME_H_

#include <memory>

namespace llvm {
class LLVMContext;
class Module;
}  // namespace llvm
namespace vmill {

// Loads the runtime for the target arch into an LLVM module.
std::unique_ptr<llvm::Module> LoadTargetRuntime(
    const std::shared_ptr<llvm::LLVMContext> &context);

}  // namespace vmill

#endif  // VMILL_BC_RUNTIME_H_
