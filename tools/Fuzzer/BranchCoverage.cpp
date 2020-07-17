/*
 * Copyright (c) 2017 Trail of Bits, nc, Inc.
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

#include <sstream>
#include <unordered_map>
#include <utility>

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <remill/BC/Version.h>

#include "vmill/Program/ShadowMemory.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Workspace/Workspace.h"

#include "tools/Fuzzer/Fuzzer.h"
#include "tools/Fuzzer/Location.h"

namespace vmill {
namespace {

static void DummyCoverSwitch(Location, const Location *,
                             const Location *) {}

static void DummyCoverBranch(Location, Location) {}

// Instruments the code so that a fuzzer can observe control flow across edges.
// This is kind of like `-fsanitize=trace-pc`.
class BranchCoverageTool : public Tool, public PersistentLocation {
 public:
  BranchCoverageTool(void)
      : PersistentLocation(kLocationTypeBranch),
        module(nullptr),
        loc_type(nullptr),
        cov_branch_func(nullptr),
        cov_switch_func(nullptr) {
    OfferSymbol("__cov_switch", DummyCoverSwitch);
    OfferSymbol("__cov_branch", DummyCoverBranch);
  }

  virtual ~BranchCoverageTool(void) {}

  // Instrument the runtime module.
  bool InstrumentRuntime(llvm::Module *module) final {
    return false;
    for (auto &func : *module) {
      if (!func.isDeclaration()) {
        InstrumentTrace(&func, 0);
      }
    }
    return true;
  }

  // Instrument a lifted function/trace.
  bool InstrumentTrace(llvm::Function *func, uint64_t pc) final {
    if (func->hasFnAttribute(llvm::Attribute::Naked)) {
      return false;
    }

    std::vector<llvm::BranchInst *> branches;
    std::vector<llvm::SwitchInst *> switches;

    for (auto &block : *func) {
      for (auto &inst : block) {
        if (auto br = llvm::dyn_cast<llvm::BranchInst>(&inst)) {
          branches.push_back(br);
        } else if (auto sw = llvm::dyn_cast<llvm::SwitchInst>(&inst)) {
          switches.push_back(sw);
        }
      }
    }

    for (auto inst : branches) {
      Instrument(inst);
    }
    for (auto inst : switches) {
      Instrument(inst);
    }

    return true;
  }

  void PrepareModule(llvm::Module *module_) override {
    module = module_;
    auto &context = module->getContext();
    auto void_type = llvm::Type::getVoidTy(context);
    loc_type = llvm::Type::getIntNTy(context, sizeof(Location) * 8);

    llvm::Type *branch_arg_types[] = {loc_type, loc_type};
    cov_branch_func = llvm::dyn_cast<llvm::Function>(
        module->getOrInsertFunction(
            "__cov_branch",
            llvm::FunctionType::get(void_type, branch_arg_types, false))
        IF_LLVM_GTE_900(.getCallee()));

    auto loc_ptr_type = llvm::PointerType::get(loc_type, 0);
    llvm::Type *switch_arg_types[] = {loc_type, loc_ptr_type, loc_ptr_type};
    cov_switch_func = llvm::dyn_cast<llvm::Function>(
        module->getOrInsertFunction(
            "__cov_switch",
            llvm::FunctionType::get(void_type, switch_arg_types, false))
        IF_LLVM_GTE_900(.getCallee()));

    CHECK_NOTNULL(cov_branch_func);
    CHECK_NOTNULL(cov_switch_func);
  }

 private:

  bool ShouldInstrumentEdge(llvm::BasicBlock *from, llvm::BasicBlock *to) {
    return to->getFirstInsertionPt() != to->end();  // Catchswitch block.
  }

  // Instrument a conditional branch instruction so that we can uniquely
  // observe the flow across each path.
  void Instrument(llvm::BranchInst *inst) {
    if (!inst->isConditional()) {
      return;
    }

    auto src_block = inst->getParent();
    auto taken_block = inst->getSuccessor(0);
    auto not_taken_block = inst->getSuccessor(1);

    llvm::Value *args[] = {
        llvm::ConstantInt::get(loc_type, loc++),
        llvm::ConstantInt::get(loc_type, loc++)};

    if (ShouldInstrumentEdge(src_block, taken_block)) {
      taken_block = BlockForEdge(src_block, taken_block);
      inst->setSuccessor(0, taken_block);
      llvm::IRBuilder<> ir(&*(taken_block->getFirstInsertionPt()));
      ir.CreateCall(cov_branch_func, args);
    }

    if (ShouldInstrumentEdge(src_block, not_taken_block)) {
      not_taken_block = BlockForEdge(src_block, not_taken_block);
      inst->setSuccessor(1, not_taken_block);
      llvm::IRBuilder<> ir(&*(not_taken_block->getFirstInsertionPt()));
      std::swap(args[0], args[1]);
      ir.CreateCall(cov_branch_func, args);
    }
  }

  // Instrument a switch instruction so that we can uniquely observe the flow
  // across each case of the switch.
  void Instrument(llvm::SwitchInst *inst) {
    auto src_block = inst->getParent();

    std::vector<Location> locs;
    std::vector<llvm::BasicBlock *> blocks;

    // Normal cases.
    const auto num_cases = inst->getNumCases();
    for (auto i = 0U; i < num_cases; ++i) {
      auto dst_block = inst->getSuccessor(i);
      if (ShouldInstrumentEdge(src_block, dst_block)) {
        dst_block = BlockForEdge(src_block, dst_block);
        inst->setSuccessor(i, dst_block);
        blocks.push_back(dst_block);
        locs.push_back(loc++);
      }
    }

    auto &context = inst->getContext();
    auto loc_array = llvm::ConstantDataArray::get(context, locs);
    auto loc_array_type = loc_array->getType();
    auto loc_var = new llvm::GlobalVariable(
        *module, loc_array_type, true,
        llvm::GlobalValue::PrivateLinkage, loc_array);

    auto zero = llvm::ConstantInt::get(loc_type, 0);
    llvm::Value *gep_indexes[] = {zero, zero};

    auto first_entry = llvm::ConstantExpr::getGetElementPtr(
        nullptr, loc_var, gep_indexes);

    gep_indexes[1] = llvm::ConstantInt::get(loc_type, locs.size());
    auto after_last_entry = llvm::ConstantExpr::getGetElementPtr(
        nullptr, loc_var, gep_indexes);

    llvm::Value *args[] = {
        nullptr,
        first_entry,
        after_last_entry};

    unsigned i = 0;
    for (auto block : blocks) {
      args[0] = llvm::ConstantInt::get(loc_type, locs[i++]);
      llvm::IRBuilder<> ir(&*block->getFirstInsertionPt());
      ir.CreateCall(cov_switch_func, args);
    }
  }

  llvm::BasicBlock *BlockForEdge(llvm::BasicBlock *from,
                                 llvm::BasicBlock *to) {
    auto &context = to->getContext();
    auto mid = llvm::BasicBlock::Create(context, "", to->getParent(), to);

    llvm::IRBuilder<> ir(mid);

    // Update all PHI nodes.
    for (auto &inst : *to) {
      auto phi = llvm::dyn_cast<llvm::PHINode>(&inst);
      if (!phi) {
        continue;
      }

      // NOTE(pag): We're explicitly not putting this in a `while` loop,
      //            because we expect that if there are more edges between
      //            `from` and `to` captured by this PHI node, then they
      //            likely represent "the other" side of some branch condition
      //            or switch block, so we will capture those later with
      //            more invocations of `BlockForEdge`.
      auto maybe_index = phi->getBasicBlockIndex(from);
      if (maybe_index == -1) {
        continue;
      }

      auto index = static_cast<unsigned>(maybe_index);

      // TODO(pag): This is kind of ugly. I wasn't sure of the right way to
      //            'forward' the PHI values correctly.
      auto tmp = ir.CreateAlloca(phi->getType());
      ir.CreateStore(phi->getIncomingValue(index), tmp);
      auto new_incoming = ir.CreateLoad(tmp);

      phi->setIncomingBlock(index, mid);
      phi->setIncomingValue(index, new_incoming);
    }

    ir.CreateBr(to);

    return mid;
  }

  llvm::Module *module;
  llvm::IntegerType *loc_type;
  llvm::Constant *cov_branch_func;
  llvm::Constant *cov_switch_func;
};

}  // namespace

std::unique_ptr<Tool> CreateBranchCoverageTracker(void) {
  return std::unique_ptr<Tool>(new BranchCoverageTool);
}

}  // namespace vmill
