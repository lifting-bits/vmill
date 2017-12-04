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
#include "remill/BC/ABI.h"
#include "remill/BC/Compat/TargetLibraryInfo.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/Arch/Decoder.h"
#include "vmill/BC/Lifter.h"
#include "vmill/BC/Trace.h"
#include "vmill/BC/Util.h"

//DEFINE_string(instruction_callback, "",
//              "Name of a function to call before each lifted instruction.");

namespace vmill {
namespace {

using FuncToTraceMap = std::unordered_map<llvm::Function *,
                                          const DecodedTrace *>;

// The function's lifted name contains both its position in memory (`pc`) and
// the contents of memory (instruction bytes). This makes it sensitive to self-
// modifying code.
static std::string LiftedFunctionName(const PC pc) {
  std::stringstream ns;
  ns << "_" << std::hex << static_cast<uint64_t>(pc);
  return ns.str();
}

class LifterImpl : public Lifter {
 public:
  virtual ~LifterImpl(void);

  explicit LifterImpl(const std::shared_ptr<llvm::LLVMContext> &);

  std::unique_ptr<llvm::Module> Lift(
        const DecodedTraceList &traces) final;

  llvm::Function *LiftTrace(const DecodedTrace &trace);


  void LiftTracesIntoModule(const FuncToTraceMap &lifted_funcs,
                            llvm::Module *module);

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
      << "Preparing module " << remill::ModuleName(semantics)
      << " for lifting " << remill::GetArchName(target_arch->arch_name)
      << " code";

  target_arch->PrepareModule(semantics.get());

  remill::ForEachISel(
      semantics.get(),
      [=] (llvm::GlobalVariable *, llvm::Function *sem) -> void {
        if (sem) {
          sem->addFnAttr(llvm::Attribute::OptimizeNone);
        }
      });
}

LifterImpl::~LifterImpl(void) {}

// Optimize the lifted function. This ends up being pretty slow because it
// goes and optimizes everything else in the module (a.k.a. semantics module).
static void RunO3(const FuncToTraceMap &funcs) {
  if (funcs.empty()) {
    return;
  }
  auto module = funcs.begin()->first->getParent();

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
  for (auto &entry : funcs) {
    func_manager.run(*(entry.first));
  }
  func_manager.doFinalization();
  module_manager.run(*module);
}

std::unique_ptr<llvm::Module> LifterImpl::Lift(
    const DecodedTraceList &traces) {

  std::unique_ptr<llvm::Module> module;

  // First off, declare the traces to be lifted.
  for (const auto &trace : traces) {
    if (!module) {
      std::stringstream ss;
      ss << std::hex << static_cast<uint64_t>(trace.pc) << "_at_"
         << static_cast<uint64_t>(trace.code_version);
      module.reset(new llvm::Module(ss.str(), *context));
    }

    const auto func_name = LiftedFunctionName(trace.pc);
    (void) remill::DeclareLiftedFunction(semantics.get(), func_name);
  }

  FuncToTraceMap lifted_funcs;
  lifted_funcs.reserve(traces.size());

  for (const auto &trace : traces) {
    lifted_funcs[LiftTrace(trace)] = &trace;
  }

  if (module) {
    LiftTracesIntoModule(lifted_funcs, module.get());
  }

  return module;
}

// Modify the lifting of function calls so that execution returns to the code
// following the call to the lifted function, or to `__remill_function_call`,
// but then we compare the current PC to what it should be had we returned
// from the function. If the PCs match, the go on as usual, otherwise return
// the memory pointer.
static void LiftPostFunctionCall(llvm::BasicBlock *call_block,
                                 llvm::BasicBlock *fall_through_block,
                                 llvm::Value *expected_ret_pc) {
  auto ret_inst = llvm::dyn_cast<llvm::ReturnInst>(call_block->getTerminator());
  CHECK_NOTNULL(ret_inst);

  ret_inst->removeFromParent();
  auto func = call_block->getParent();
  auto mod = func->getParent();
  auto unexpected_pc_block = llvm::BasicBlock::Create(
      mod->getContext(), "", func);
  auto pc_after_call = remill::LoadProgramCounter(call_block);

  llvm::IRBuilder<> ir(call_block);
  ir.CreateCondBr(ir.CreateICmpEQ(expected_ret_pc, pc_after_call),
                  fall_through_block, unexpected_pc_block);

  llvm::IRBuilder<> ir2(unexpected_pc_block);
  ir2.CreateRet(ret_inst->getReturnValue());

  delete ret_inst;
}

llvm::Function *LifterImpl::LiftTrace(const DecodedTrace &trace) {

  const auto &insts = trace.instructions;
  const auto func_name = LiftedFunctionName(trace.pc);

  auto func = semantics->getFunction(func_name);
  CHECK(nullptr != func)
      << "Broken invariant: the trace function " << func_name
      << " has not yet been declared.";

  CHECK(func->isDeclaration());

  auto context_ptr = context.get();

  remill::CloneBlockFunctionInto(func);

  // Function that will create basic blocks as needed.
  std::unordered_map<uint64_t, llvm::BasicBlock *> blocks;
  auto GetOrCreateBlock = [func, context_ptr, &blocks] (PC block_pc) {
    auto &block = blocks[static_cast<uint64_t>(block_pc)];
    if (!block) {
      block = llvm::BasicBlock::Create(*context_ptr, "", func);
    }
    return block;
  };

  // Create a branch from the entrypoint of the lifted function to the basic
  // block representing the first decoded instruction.
  auto entry_block = GetOrCreateBlock(trace.pc);
  llvm::BranchInst::Create(entry_block, &(func->front()));

  // Guarantee that a basic block exists, even if the first instruction
  // failed to decode.
  if (!insts.count(trace.pc)) {
    remill::AddTerminatingTailCall(entry_block, intrinsics.error);
  }

//  llvm::Constant *callback = nullptr;
//  llvm::Value *memory_ptr_ref = nullptr;
//  if (!FLAGS_instruction_callback.empty()) {
//    callback = module->getOrInsertFunction(
//        FLAGS_instruction_callback, func->getFunctionType());
//    memory_ptr_ref = remill::LoadMemoryPointerRef(entry_block);
//  }

  // Lift each instruction into its own basic block.
  for (const auto &entry : insts) {
    auto block = GetOrCreateBlock(entry.first);
    auto &inst = const_cast<remill::Instruction &>(entry.second);

    inst.FinalizeDecode();

//    if (callback) {
//      llvm::IRBuilder<> ir(block);
//      ir.CreateStore(ir.CreateCall(callback, remill::LiftedFunctionArgs(block)),
//                     memory_ptr_ref);
//    }

    llvm::Value *ret_pc = nullptr;
    if (inst.IsFunctionCall()) {
      auto pc = remill::LoadProgramCounter(block);
      llvm::IRBuilder<> ir(block);
      ret_pc = ir.CreateAdd(
          pc, llvm::ConstantInt::get(pc->getType(), inst.NumBytes()));
    }

    if (remill::kLiftedInstruction != lifter.LiftIntoBlock(inst, block)) {
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
        llvm::BranchInst::Create(
            GetOrCreateBlock(static_cast<PC>(inst.next_pc)),
            block);
        break;

      case remill::Instruction::kCategoryDirectJump:
        llvm::BranchInst::Create(
            GetOrCreateBlock(static_cast<PC>(inst.branch_taken_pc)),
            block);
        break;
      case remill::Instruction::kCategoryIndirectJump:
        remill::AddTerminatingTailCall(block, intrinsics.jump);
        break;

      case remill::Instruction::kCategoryDirectFunctionCall:
        if (inst.branch_taken_pc != inst.next_pc) {

          const auto target_func_name = LiftedFunctionName(
              static_cast<PC>(inst.branch_taken_pc));

          auto target_func = semantics->getFunction(target_func_name);
          if (!target_func) {
            remill::AddTerminatingTailCall(block, intrinsics.function_call);
          } else {
            remill::AddTerminatingTailCall(block, target_func);
          }

          LiftPostFunctionCall(
              block, GetOrCreateBlock(static_cast<PC>(inst.next_pc)), ret_pc);
        }
        break;

      case remill::Instruction::kCategoryIndirectFunctionCall:
        remill::AddTerminatingTailCall(block, intrinsics.function_call);
        LiftPostFunctionCall(
            block, GetOrCreateBlock(static_cast<PC>(inst.next_pc)), ret_pc);
        break;

      case remill::Instruction::kCategoryFunctionReturn:
        remill::AddTerminatingTailCall(block, intrinsics.function_return);
        break;

      case remill::Instruction::kCategoryConditionalBranch:
      case remill::Instruction::kCategoryConditionalAsyncHyperCall:
        llvm::BranchInst::Create(
            GetOrCreateBlock(static_cast<PC>(inst.branch_taken_pc)),
            GetOrCreateBlock(static_cast<PC>(inst.branch_not_taken_pc)),
            remill::LoadBranchTaken(block), block);
        break;

      // Lift async hyper calls in such a way that the call graph structure
      // is maintained. Specifically, if we imagine these hyper calls as being
      // system call instructions, then most likely they are wrapped inside of
      // another function, and we eventually want to reach the function return
      // instruction, so that the lifted caller can continue on.
      case remill::Instruction::kCategoryAsyncHyperCall:
        remill::AddTerminatingTailCall(block, intrinsics.async_hyper_call);
        block->getTerminator()->eraseFromParent();
        remill::AddTerminatingTailCall(block, intrinsics.jump);
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

  return func;
}

void LifterImpl::LiftTracesIntoModule(const FuncToTraceMap &lifted_funcs,
                                      llvm::Module *module) {

  RunO3(lifted_funcs);  // Optimize the lifted functions.

  auto context_ptr = context.get();

  // Move the optimized functions into the target module, and add in code
  // cache index entries.
  for (const auto &entry : lifted_funcs) {
    auto func = entry.first;
    const auto &trace = *(entry.second);
    MoveFunctionIntoModule(func, module);

    std::vector<llvm::Type *> types(2);
    std::vector<llvm::Constant *> values(2);

    // TraceId type.
    types[0] = llvm::Type::getInt64Ty(*context_ptr);
    types[1] = llvm::Type::getIntNTy(*context_ptr, sizeof(trace.id.hash) * 8);
    auto trace_id_type = llvm::StructType::get(*context_ptr, types, true);

    values[0] = llvm::ConstantInt::get(
        types[0], static_cast<uint64_t>(trace.id.pc));

    values[1] = llvm::ConstantInt::get(
        types[1], static_cast<TraceHashBaseType>(trace.id.hash));

    auto trace_id_val = llvm::ConstantStruct::get(trace_id_type, values);

    // TraceEntry type.
    types[0] = trace_id_type;
    types[1] = func->getType();
    auto trace_entry_type = llvm::StructType::get(*context_ptr, types, true);

    values[0] = trace_id_val;
    values[1] = func;
    auto trace_entry_val = llvm::ConstantStruct::get(trace_entry_type, values);

    CHECK(!func->isDeclaration())
        << "Lifted function " << func->getName().str()
        << " was declared but not defined.";

    // Add an entry into the `.translations` section for this block. These
    // entries will end up being contiguous in memory.
    auto var = new llvm::GlobalVariable(
        *module, trace_entry_type, true, llvm::GlobalValue::ExternalLinkage,
        trace_entry_val);
    var->setSection(".translations");
    var->setAlignment(8);
  }

  for (const auto &entry : lifted_funcs) {
    auto func = entry.first;
    func->setName("");  // Kill its name.
    func->setLinkage(llvm::GlobalValue::PrivateLinkage);
    func->setVisibility(llvm::GlobalValue::HiddenVisibility);
  }
}

}  // namespace

std::unique_ptr<Lifter> Lifter::Create(
    const std::shared_ptr<llvm::LLVMContext> &context) {
  return std::unique_ptr<Lifter>(new LifterImpl(context));
}

Lifter::Lifter(void) {}
Lifter::~Lifter(void) {}

}  // namespace vmill
