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
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>

#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/DeadStoreEliminator.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/Arch/Decoder.h"
#include "vmill/BC/Lifter.h"
#include "vmill/BC/Optimize.h"
#include "vmill/BC/Trace.h"
#include "vmill/BC/Util.h"

DEFINE_string(instruction_callback, "",
              "Name of a function to call before each lifted instruction.");

DEFINE_bool(check_pcs, false, "Check program counters on block entry.");

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

// Modify the lifting of function calls so that execution returns to the code
// following the call to the lifted function, or to `__remill_function_call`,
// but then we compare the current PC to what it should be had we returned
// from the function. If the PCs match, the go on as usual, otherwise return
// the memory pointer.
static void LiftPostFunctionCall(llvm::BasicBlock *call_block,
                                 llvm::BasicBlock *fall_through_block,
                                 llvm::Value *expected_ret_pc,
                                 llvm::Value *ret_mem_ptr) {

  auto func = call_block->getParent();
  auto mod = func->getParent();
  auto unexpected_pc_block = llvm::BasicBlock::Create(
      mod->getContext(), "", func);
  auto pc_after_call = remill::LoadProgramCounter(call_block);
  remill::StoreNextProgramCounter(call_block, pc_after_call);

  llvm::IRBuilder<> ir(call_block);
  ir.CreateCondBr(ir.CreateICmpEQ(expected_ret_pc, pc_after_call),
                  fall_through_block, unexpected_pc_block);

  // If the return address doesn't match, then we'll unwind the return addresses
  // until we get to a matching one or until we get to main dispatcher and
  // need to re-lift.
  auto fallback_func = mod->getOrInsertFunction("__vmill_unwind_return",
                                                func->getFunctionType());
  remill::AddTerminatingTailCall(
      unexpected_pc_block, fallback_func IF_LLVM_GTE_900(.getCallee()));
}

// Create the metadata node from a constant integer representing the trace
// entry PC.
static llvm::MDNode *CreatePCAnnotation(llvm::Constant *pc) {
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
  auto addr_md = llvm::ValueAsMetadata::get(pc);
  return llvm::MDNode::get(pc->getContext(), addr_md);
#else
  return llvm::MDNode::get(pc->getContext(), pc);
#endif
}

// Clear out LLVM variable names. They're usually not helpful.
static void ClearVariableNames(llvm::Function *func) {
  for (auto &block : *func) {
    block.setName("");
    for (auto &inst : block) {
      if (inst.hasName()) {
        inst.setName("");
      }
    }
  }
}

// Optimize a function.
static void OptimizeFunction(llvm::Function *func) {
  std::vector<llvm::CallInst *> calls_to_inline;
  for (auto changed = true; changed; changed = !calls_to_inline.empty()) {
    calls_to_inline.clear();

    for (auto &block : *func) {
      for (auto &inst : block) {
        if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst); call_inst) {
          if (auto called_func = call_inst->getCalledFunction();
              called_func && !called_func->isDeclaration() &&
              !called_func->hasFnAttribute(llvm::Attribute::NoInline)) {
            calls_to_inline.push_back(call_inst);
          }
        }
      }
    }

    for (auto call_inst : calls_to_inline) {
      llvm::InlineFunctionInfo info;
#if LLVM_VERSION_NUMBER < LLVM_VERSION(11, 0)
      llvm::InlineFunction(call_inst, info);
#else
      llvm::InlineFunction(*call_inst, info);
#endif
    }
  }

  // Initialize cleanup optimizations
  llvm::legacy::FunctionPassManager fpm(func->getParent());
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createPromoteMemoryToRegisterPass());
  fpm.add(llvm::createReassociatePass());
  fpm.add(llvm::createDeadStoreEliminationPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createSROAPass());
  fpm.doInitialization();
  fpm.run(*func);
  fpm.doFinalization();

  ClearVariableNames(func);
}

}  // namespace

class LifterImpl{
 public:
  explicit LifterImpl(const remill::Arch *arch_,
                      const std::shared_ptr<llvm::LLVMContext> &);

  std::unique_ptr<llvm::Module> Lift(const DecodedTraceList &traces);

  llvm::Function *LiftTrace(const DecodedTrace &trace);

  void LiftTracesIntoModule(const FuncToTraceMap &lifted_funcs,
                            llvm::Module *module);

  const remill::Arch * const arch;

  // LLVM context that manages all modules.
  const std::shared_ptr<llvm::LLVMContext> context;

  // Bitcode semantics for the target architecture.
  const std::unique_ptr<llvm::Module> semantics;

  // For dead store elimination.
  const std::vector<remill::StateSlot> slots;

  // Tracks the Remill intrinsics present in `semantics`.
  const remill::IntrinsicTable intrinsics;

  // The `__remill_basic_block` function.
  llvm::Function * const bb_func;

  // Lifts instructions from the target architecture to bitcode that can run
  // on the host architecture.
  remill::InstructionLifter lifter;

  // Metadata ID for program counters.
  const unsigned pc_metadata_id;

  llvm::Function *instruction_callback{nullptr};

 private:
  LifterImpl(void) = delete;
};

LifterImpl::LifterImpl(const remill::Arch *arch_,
                       const std::shared_ptr<llvm::LLVMContext> &context_)
    : arch(arch_),
      context(context_),
      semantics(remill::LoadArchSemantics(arch)),
      slots(remill::StateSlots(arch, semantics.get())),
      intrinsics(semantics.get()),
      bb_func(remill::BasicBlockFunction(semantics.get())),
      lifter(arch, &intrinsics),
      pc_metadata_id(context->getMDKindID("PC")) {

  LOG(INFO)
      << "Preparing module " << remill::ModuleName(semantics)
      << " for lifting " << remill::GetArchName(arch->arch_name)
      << " code";

  arch->PrepareModule(semantics.get());

  if (!FLAGS_instruction_callback.empty()) {
    instruction_callback = llvm::dyn_cast<llvm::Function>(
        semantics->getOrInsertFunction(
        FLAGS_instruction_callback, arch->LiftedFunctionType())
        IF_LLVM_GTE_900(.getCallee()));
  }
}

std::unique_ptr<llvm::Module> LifterImpl::Lift(
    const DecodedTraceList &traces) {

  std::unique_ptr<llvm::Module> module;

  // First off, declare the traces to be lifted.
  for (const DecodedTrace &trace : traces) {
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

  // Hard-code the trace address into the bitcode.
  auto func_entry_block = &(func->front());
  auto state_ptr = remill::NthArgument(func, remill::kStatePointerArgNum);
  auto next_pc_ptr = remill::LoadNextProgramCounterRef(func_entry_block);
  auto pc_ptr = remill::LoadProgramCounterRef(func_entry_block);
  auto pc_type = llvm::Type::getIntNTy(*context_ptr, arch->address_size);

  // Store the program counter in.
  do {
    const auto pc = remill::NthArgument(func, remill::kPCArgNum);
    llvm::IRBuilder<> ir(func_entry_block);
    ir.CreateStore(pc, next_pc_ptr);
    ir.CreateStore(pc, pc_ptr);
  } while (false);

  llvm::BasicBlock *out_of_sync_block = nullptr;
  if (FLAGS_check_pcs) {
    auto sync_func = semantics->getOrInsertFunction(
        "__vmill_out_of_sync", func->getFunctionType());

    out_of_sync_block = llvm::BasicBlock::Create(*context_ptr, "", func);
    remill::AddCall(
        out_of_sync_block, sync_func IF_LLVM_GTE_900(.getCallee()));
    remill::AddTerminatingTailCall(
        out_of_sync_block, intrinsics.error);
  }

  // Function that will create basic blocks as needed.
  std::unordered_map<uint64_t, std::pair<llvm::BasicBlock *, llvm::BasicBlock *>> blocks;
  auto GetOrCreateBlock = \
      [=, &blocks] (PC block_pc_) {
        const auto block_pc = static_cast<uint64_t>(block_pc_);
        auto &block_pair = blocks[block_pc];

        if (!block_pair.first) {
          std::stringstream ss;
          ss << std::hex << block_pc;
          block_pair.first = llvm::BasicBlock::Create(*context_ptr, ss.str(), func);
          if (!out_of_sync_block) {
            block_pair.second = block_pair.first;
            return block_pair.first;
          }

          llvm::IRBuilder<> ir(block_pair.first);
          auto exp_pc_val = llvm::ConstantInt::get(pc_type, block_pc, false);
          auto dyn_pc_val = ir.CreateLoad(pc_type, next_pc_ptr);
          auto pcs_in_sync = ir.CreateICmpEQ(exp_pc_val, dyn_pc_val);
          auto in_sync_block = llvm::BasicBlock::Create(*context_ptr, "", func);
          ir.CreateCondBr(pcs_in_sync, in_sync_block, out_of_sync_block);
          block_pair.second = in_sync_block;
        }
        return block_pair.first;
      };

  // Create a branch from the entrypoint of the lifted function to the basic
  // block representing the first decoded instruction.
  auto entry_block = GetOrCreateBlock(trace.pc);
  llvm::BranchInst::Create(entry_block, func_entry_block);

  // Guarantee that a basic block exists, even if the first instruction
  // failed to decode.
  if (!insts.count(trace.pc)) {
    remill::AddTerminatingTailCall(entry_block, intrinsics.error);
    OptimizeFunction(func);
    return func;
  }

  llvm::Constant *callback = nullptr;
  llvm::Value *memory_ptr_ref = nullptr;
  if (instruction_callback) {
    callback = instruction_callback;
    memory_ptr_ref = remill::LoadMemoryPointerRef(entry_block);
  }

  // Lift each instruction into its own basic block.
  for (const auto &entry : insts) {
    (void) GetOrCreateBlock(entry.first);
    auto block = blocks[static_cast<uint64_t>(entry.first)].second;
    if (!block->empty()) {
      continue;
    }

    auto &inst = const_cast<remill::Instruction &>(entry.second);

    if (callback) {
      llvm::Value *args[remill::kNumBlockArgs];
      args[remill::kStatePointerArgNum] = state_ptr;
      args[remill::kPCArgNum] = lifter.LoadRegValue(
          block, state_ptr, remill::kNextPCVariableName);
      llvm::IRBuilder<> ir(block);
      args[remill::kMemoryPointerArgNum] = ir.CreateLoad(memory_ptr_ref);
      ir.CreateStore(ir.CreateCall(callback, args), memory_ptr_ref);
    }

    llvm::ConstantInt *ret_pc = nullptr;
    if (inst.IsFunctionCall()) {
      ret_pc = llvm::ConstantInt::get(pc_type, inst.branch_not_taken_pc, false);
    }

    const auto lift_status = lifter.LiftIntoBlock(inst, block, state_ptr);
    if (remill::kLiftedInstruction != lift_status) {
      remill::AddTerminatingTailCall(block, intrinsics.error);
      continue;
    }

//    if (inst.pc == 0xf7f41c72u) {
//      LOG(ERROR) << remill::LLVMThingToString(func);
//    }
    CHECK(!arch->MayHaveDelaySlot(inst))
        << "TODO: Delay slots are not yet handled in VMill";

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
        if (inst.branch_taken_pc != inst.branch_not_taken_pc) {

          const auto target_func_name = LiftedFunctionName(
              static_cast<PC>(inst.branch_taken_pc));

          auto target_func = semantics->getFunction(target_func_name);
          llvm::Value *mem_ptr = nullptr;
          if (!target_func) {
            mem_ptr = remill::AddCall(block, intrinsics.function_call);

          } else {
            mem_ptr = remill::AddCall(block, target_func);
          }

          LiftPostFunctionCall(
              block, GetOrCreateBlock(static_cast<PC>(inst.branch_not_taken_pc)),
              ret_pc, mem_ptr);

        // `call $+5` pattern.
        } else {
          llvm::BranchInst::Create(
              GetOrCreateBlock(static_cast<PC>(inst.branch_not_taken_pc)),
              block);
        }
        break;

      case remill::Instruction::kCategoryIndirectFunctionCall: {
        auto mem_ptr = remill::AddCall(block, intrinsics.function_call);
        LiftPostFunctionCall(
            block, GetOrCreateBlock(static_cast<PC>(inst.branch_not_taken_pc)),
            ret_pc, mem_ptr);
        break;
      }

      case remill::Instruction::kCategoryFunctionReturn:
        remill::AddTerminatingTailCall(block, intrinsics.function_return);
        break;

      case remill::Instruction::kCategoryConditionalBranch:
        llvm::BranchInst::Create(
            GetOrCreateBlock(static_cast<PC>(inst.branch_taken_pc)),
            GetOrCreateBlock(static_cast<PC>(inst.branch_not_taken_pc)),
            remill::LoadBranchTaken(block), block);
        break;

      case remill::Instruction::kCategoryConditionalAsyncHyperCall: {
        const auto cond = remill::LoadBranchTaken(block);
        const auto taken_block = llvm::BasicBlock::Create(*context_ptr, "", func);
        const auto not_taken_block = llvm::BasicBlock::Create(*context_ptr, "", func);
        llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);

        remill::AddCall(taken_block, intrinsics.async_hyper_call);
        remill::AddTerminatingTailCall(taken_block, intrinsics.jump);

        llvm::BranchInst::Create(
            GetOrCreateBlock(static_cast<PC>(inst.branch_not_taken_pc)),
            not_taken_block);
        break;
      }

      // Lift async hyper calls in such a way that the call graph structure
      // is maintained. Specifically, if we imagine these hyper calls as being
      // system call instructions, then most likely they are wrapped inside of
      // another function, and we eventually want to reach the function return
      // instruction, so that the lifted caller can continue on.
      case remill::Instruction::kCategoryAsyncHyperCall:
        remill::AddCall(block, intrinsics.async_hyper_call);
        remill::AddTerminatingTailCall(block, intrinsics.jump);
        break;
    }
  }

  // Terminate any stragglers.
  for (auto pc_to_block : blocks) {
    auto block = pc_to_block.second.second;
    if (!block->getTerminator()) {
      remill::AddTerminatingTailCall(block, intrinsics.missing_block);
    }
  }

  OptimizeFunction(func);
  return func;
}

void LifterImpl::LiftTracesIntoModule(const FuncToTraceMap &lifted_funcs,
                                      llvm::Module *module) {
  auto context_ptr = context.get();
  auto int8_ptr_type  = llvm::Type::getInt8PtrTy(module->getContext());

  std::vector<llvm::Constant *> used_list;

  // Move the optimized functions into the target module, and add in code
  // cache index entries.
  for (const auto &entry : lifted_funcs) {
    auto func = entry.first;
    const auto &trace = *(entry.second);
    remill::MoveFunctionIntoModule(func, module);

    std::vector<llvm::Type *> types(2);
    std::vector<llvm::Constant *> values(2);

    // TraceId type.
    types[0] = llvm::Type::getInt64Ty(*context_ptr);
    types[1] = llvm::Type::getIntNTy(*context_ptr, sizeof(trace.id.hash) * 8);
    auto trace_id_type = llvm::StructType::get(*context_ptr, types, true);

    auto pc_uint = static_cast<uint64_t>(trace.id.pc);
    auto pc = llvm::ConstantInt::get(types[0], pc_uint);
    func->setMetadata(pc_metadata_id, CreatePCAnnotation(pc));
    values[0] = pc;

    auto hash_uint = static_cast<TraceHashBaseType>(trace.id.hash);
    values[1] = llvm::ConstantInt::get(types[1], hash_uint);

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

    // Things in the use list must have named.
    std::stringstream ss;
    ss << std::hex << pc_uint << "_" << hash_uint;
    auto name = ss.str();

    // Add an entry into the `.DATA,index` section for this block. These
    // entries will end up being contiguous in memory.
    auto var = new llvm::GlobalVariable(
        *module, trace_entry_type, true, llvm::GlobalValue::PrivateLinkage,
        trace_entry_val, name);
#ifdef __APPLE__
    var->setSection(".__DATA,.vindex");
#else
    var->setSection(".vindex");
#endif
#if LLVM_VERSION_NUMBER < LLVM_VERSION(10, 0)
    var->setAlignment(8);
#else
    var->setAlignment(llvm::MaybeAlign(8));
#endif

    used_list.push_back(llvm::ConstantExpr::getBitCast(var, int8_ptr_type));
  }

  // Mark all the translations as used.
  auto used_type = llvm::ArrayType::get(int8_ptr_type, used_list.size());
  auto used = new llvm::GlobalVariable(
      *module, used_type, false, llvm::GlobalValue::AppendingLinkage,
      llvm::ConstantArray::get(used_type, used_list), "llvm.used");
  used->setSection("llvm.metadata");

  remill::RemoveDeadStores(arch, module, bb_func, slots);

  // Kill off all the function names.
  for (const auto &entry : lifted_funcs) {
    auto func = entry.first;
//
//    if (static_cast<uint64_t>(entry.second->pc) == 0xf7f41c70u) {
//      LOG(ERROR) << remill::LLVMThingToString(func);
//    }
    func->setName("");  // Kill its name.
    func->setLinkage(llvm::GlobalValue::PrivateLinkage);
    func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  }
}

Lifter::Lifter(const remill::Arch *arch_,
               const std::shared_ptr<llvm::LLVMContext> &context_)
    : impl(new LifterImpl(arch_, context_)) {}

Lifter::~Lifter(void) {}

// Lift a list of decoded traces into a new LLVM bitcode module, and
// return the resulting module.
std::unique_ptr<llvm::Module> Lifter::Lift(
    const DecodedTraceList &traces) const {
  return impl->Lift(traces);
}

}  // namespace vmill
