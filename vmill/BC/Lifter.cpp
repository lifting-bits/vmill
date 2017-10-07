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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <llvm/ADT/Triple.h>

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

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/Compat/TargetLibraryInfo.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/Arch/Decoder.h"
#include "vmill/BC/Lifter.h"

namespace vmill {
namespace {

class LifterImpl : public Lifter {
 public:
  virtual ~LifterImpl(void);

  explicit LifterImpl(const std::shared_ptr<llvm::LLVMContext> &);

  llvm::Function *LiftTraceIntoModule(
      const DecodedTrace &trace, llvm::Module *module) override;

  // LLVM context that manages all modules.
  const std::shared_ptr<llvm::LLVMContext> context;

  // Bitcode semantics for the target architecture.
  const std::unique_ptr<llvm::Module> semantics;

  // Tracks the Remill intrinsics present in `semantics`.
  remill::IntrinsicTable intrinsics;

  // Lifts instructions from the target architecture to bitcode that can run
  // on the host architecture.
  remill::InstructionLifter lifter;

 private:
  LifterImpl(void) = delete;
};

LifterImpl::LifterImpl(const std::shared_ptr<llvm::LLVMContext> &context_)
    : Lifter(),
      context(context_),
      semantics(remill::LoadTargetSemantics(context.get())),
      intrinsics(semantics.get()),
      lifter(remill::AddressType(semantics.get()), &intrinsics) {

  auto target_arch = remill::GetTargetArch();

  LOG(INFO)
      << "Preparing module " << semantics->getName().str() << " for lifting "
      << remill::GetArchName(target_arch->arch_name) << " code";

  target_arch->PrepareModule(semantics.get());

  remill::ForEachISel(
      semantics.get(),
      [=] (llvm::GlobalVariable *, llvm::Function *sem) -> void {
        sem->addFnAttr(llvm::Attribute::OptimizeNone);
      });
}

LifterImpl::~LifterImpl(void) {}

// The function's lifted name contains both its position in memory (`pc`) and
// the contents of memory (instruction bytes). This makes it sensitive to self-
// modifying code.
static std::string LiftedFunctionName(uint64_t pc, uint64_t hash) {
  std::stringstream ns;
  ns << "_" << std::hex << pc << "_" << std::hex << hash;
  return ns.str();
}

#if 0
static llvm::Constant *CloneConstant(llvm::Constant *val);

static std::vector<llvm::Constant *> CloneContents(
    llvm::ConstantAggregate *agg) {
  auto num_elems = agg->getNumOperands();
  std::vector<llvm::Constant *> clones(num_elems);
  for (auto i = 0U; i < num_elems; ++i) {
    clones[i] = CloneConstant(agg->getAggregateElement(i));
  }
  return clones;
}

static llvm::Constant *CloneConstant(llvm::Constant *val) {
  if (llvm::isa<llvm::ConstantData>(val) ||
      llvm::isa<llvm::ConstantAggregateZero>(val)) {
    return val;
  }

  std::vector<llvm::Constant *> elements;
  if (auto agg = llvm::dyn_cast<llvm::ConstantAggregate>(val)) {
    CloneContents(agg);
  }

  if (auto arr = llvm::dyn_cast<llvm::ConstantArray>(val)) {
    return llvm::ConstantArray::get(arr->getType(), elements);

  } else if (auto vec = llvm::dyn_cast<llvm::ConstantVector>(val)) {
    return llvm::ConstantVector::get(elements);

  } else if (auto obj = llvm::dyn_cast<llvm::ConstantStruct>(val)) {
    return llvm::ConstantStruct::get(obj->getType(), elements);

  } else {
    LOG(FATAL)
        << "Cannot clone " << remill::LLVMThingToString(val);
    return val;
  }
}

#endif

static llvm::Function *DeclareFunctionInModule(llvm::Function *func,
                                               llvm::Module *dest_module) {
  auto dest_func = dest_module->getFunction(func->getName());
  if (dest_func) {
    return dest_func;
  }

  dest_func = llvm::Function::Create(
      func->getFunctionType(), func->getLinkage(),
      func->getName(), dest_module);

  dest_func->copyAttributesFrom(func);
  dest_func->setVisibility(func->getVisibility());

  return dest_func;
}

static llvm::GlobalVariable *DeclareVarInModule(llvm::GlobalVariable *var,
                                                llvm::Module *dest_module) {
  auto dest_var = dest_module->getGlobalVariable(var->getName());
  if (dest_var) {
    return dest_var;
  }

  auto type = var->getValueType();
  dest_var = new llvm::GlobalVariable(
      *dest_module, type, var->isConstant(), var->getLinkage(), nullptr,
      var->getName(), nullptr, var->getThreadLocalMode(),
      var->getType()->getAddressSpace());

  dest_var->copyAttributesFrom(var);

  if (var->hasInitializer()) {
    auto initializer = var->getInitializer();
    CHECK(!initializer->needsRelocation())
        << "Initializer of global " << var->getName().str()
        << " cannot be trivially copied to the destination module.";

    dest_var->setInitializer(initializer);
  }

  return dest_var;
}

template <typename T>
static void ClearMetaData(T *value) {
  llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 4> mds;
  value->getAllMetadata(mds);
  for (auto md_info : mds) {
    value->setMetadata(md_info.first, nullptr);
  }
}

// Move a function from one module into another module.
static void MoveFunctionIntoModule(llvm::Function *func,
                                   llvm::Module *dest_module) {
  CHECK(&(func->getContext()) == &(dest_module->getContext()))
      << "Cannot move function across two independent LLVM contexts.";

  auto source_module = func->getParent();
  CHECK(source_module != dest_module)
      << "Cannot move function to the same module.";

  CHECK(!dest_module->getFunction(func->getName()))
      << "Function " << func->getName().str()
      << " already exists in destination module.";

  func->removeFromParent();
  dest_module->getFunctionList().push_back(func);

  ClearMetaData(func);

  for (auto &block : *func) {
    for (auto &inst : block) {
      ClearMetaData(&inst);

      // Substitute globals in the operands.
      for (auto &op : inst.operands()) {
        auto used_val = op.get();
        auto used_func = llvm::dyn_cast<llvm::Function>(used_val);
        auto used_var = llvm::dyn_cast<llvm::GlobalVariable>(used_val);
        if (used_func) {
          op.set(DeclareFunctionInModule(used_func, dest_module));

        } else if (used_var) {
          op.set(DeclareVarInModule(used_var, dest_module));

        } else {
          CHECK(!llvm::isa<llvm::GlobalValue>(used_val))
              << "Cannot move global value " << used_val->getName().str()
              << " into destination module.";
        }
      }
    }
  }
}

// Optimize the lifted function. This ends up being pretty slow because it
// goes and optimizes everything else in the module (a.k.a. semantics module).
static void RunO3(llvm::Function *func) {
  auto module = func->getParent();

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
  builder.VerifyInput = true;
  builder.VerifyOutput = true;

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);
  func_manager.doInitialization();
  func_manager.run(*func);
  func_manager.doFinalization();
  module_manager.run(*module);
}

llvm::Function *LifterImpl::LiftTraceIntoModule(
    const DecodedTrace &trace, llvm::Module *module) {

  const auto &insts = trace.instructions;
  const auto func_name = LiftedFunctionName(trace.entry_pc, trace.hash);

  auto context_ptr = context.get();
  CHECK(context_ptr == &(module->getContext()));

  // Already lifted; don't re-do things.
  auto dest_func = module->getFunction(func_name);
  if (dest_func) {
    return dest_func;
  }

  auto func = remill::DeclareLiftedFunction(semantics.get(), func_name);
  remill::CloneBlockFunctionInto(func);

  // Function that will create basic blocks as needed.
  std::unordered_map<uint64_t, llvm::BasicBlock *> blocks;
  auto GetOrCreateBlock = [func, context_ptr, &blocks] (uint64_t block_pc) {
    auto &block = blocks[block_pc];
    if (!block) {
      block = llvm::BasicBlock::Create(*context_ptr, "", func);
    }
    return block;
  };

  // Create a branch from the entrypoint of the lifted function to the basic
  // block representing the first decoded instruction.
  auto entry_block = GetOrCreateBlock(trace.entry_pc);
  llvm::BranchInst::Create(entry_block, &(func->front()));

  // Guarantee that a basic block exists, even if the first instruction
  // failed to decode.
  if (!insts.count(trace.entry_pc)) {
    remill::AddTerminatingTailCall(entry_block, intrinsics.error);
  }

  // Lift each instruction into its own basic block.
  for (const auto &entry : insts) {
    auto block = GetOrCreateBlock(entry.first);
    auto &inst = const_cast<remill::Instruction &>(entry.second);
    if (!lifter.LiftIntoBlock(inst, block)) {
      remill::AddTerminatingTailCall(block, intrinsics.error);
      continue;
    }

    // Connect together the basic blocks.
    switch (inst.category) {
      case remill::Instruction::kCategoryInvalid:
      case remill::Instruction::kCategoryError:
        remill::AddTerminatingTailCall(block, intrinsics.error);
        break;

      case remill::Instruction::kCategoryNormal:
      case remill::Instruction::kCategoryNoOp:
        llvm::BranchInst::Create(GetOrCreateBlock(inst.next_pc), block);
        break;

      case remill::Instruction::kCategoryDirectJump:
        llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc),
                                 block);
        break;
      case remill::Instruction::kCategoryIndirectJump:
        remill::AddTerminatingTailCall(block, intrinsics.jump);
        break;

      // Lift direct and indirect functions calls to go through the
      // `__remill_function_call` intrinsic, even though the direct targets
      // will have been lifted.
      case remill::Instruction::kCategoryDirectFunctionCall:
      case remill::Instruction::kCategoryIndirectFunctionCall:
        remill::AddTerminatingTailCall(block, intrinsics.function_call);
        break;

      case remill::Instruction::kCategoryFunctionReturn:
        remill::AddTerminatingTailCall(block, intrinsics.function_return);
        break;

      case remill::Instruction::kCategoryConditionalBranch:
      case remill::Instruction::kCategoryConditionalAsyncHyperCall:
        llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc),
                                 GetOrCreateBlock(inst.branch_not_taken_pc),
                                 remill::LoadBranchTaken(block), block);
        break;

      case remill::Instruction::kCategoryAsyncHyperCall:
        remill::AddTerminatingTailCall(block, intrinsics.async_hyper_call);
        break;
    }
  }

  // Terminate any stragglers.
  for (auto pc_to_block : blocks) {
    auto block = pc_to_block.second;
    if (!block->getTerminator()) {
      remill::AddTerminatingTailCall(block, intrinsics.missing_block);
    }
  }

  // Optimize the lifted function.
  RunO3(func);

  MoveFunctionIntoModule(func, module);

  return func;
}

}  // namespace

Lifter *Lifter::Create(
    const std::shared_ptr<llvm::LLVMContext> &context) {
  return new LifterImpl(context);
}

Lifter::Lifter(void) {}
Lifter::~Lifter(void) {}

}  // namespace vmill
