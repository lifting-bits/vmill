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

#include <llvm/IR/Function.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/BC/Compat/TargetLibraryInfo.h"

#include "vmill/BC/Optimize.h"

namespace vmill {

void OptimizeModule(llvm::Module *module,
                    std::function<llvm::Function *(void)> generator) {
  llvm::legacy::FunctionPassManager func_manager(module);
  llvm::legacy::PassManager module_manager;

  auto TLI = new llvm::TargetLibraryInfoImpl(
      llvm::Triple(module->getTargetTriple()));

  TLI->disableAllFunctions();  // `-fno-builtin`.

  llvm::PassManagerBuilder builder;
  builder.OptLevel = 3;
  builder.SizeLevel = 0;
  builder.Inliner = llvm::createFunctionInliningPass(
      std::numeric_limits<int>::max());
  builder.LibraryInfo = TLI;  // Deleted by `llvm::~PassManagerBuilder`.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  builder.DisableUnitAtATime = false;
  builder.RerollLoops = false;
  builder.SLPVectorize = false;
  builder.LoopVectorize = false;
  IF_LLVM_GTE_36(builder.VerifyInput = true;)
  IF_LLVM_GTE_36(builder.VerifyOutput = true;)

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);
  func_manager.doInitialization();
  llvm::Function *func = nullptr;
  while (nullptr != (func = generator())) {
    func_manager.run(*func);
  }
  func_manager.doFinalization();
  module_manager.run(*module);
}

}  // namespace vmill
