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

#include <glog/logging.h>

#include <string>
#include <sstream>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "remill/BC/Util.h"

#include "tools/taint/TaintTracker.h"

// TODO(pag): Eventual idea would be to move the core instrumentation into
//            lots of helper functions, so that instead of real and tainted
//            operations being interleaved, we do a series of real operations,
//            perhaps recording key things like memory addresses accessed,
//            then call a function that represents all the taint propagation
//            calls that need to happen.

namespace vmill {
namespace {

static uint64_t ReturnUntainted(void) {
  return 0;
}

}  // namespace

TaintTrackerTool::TaintTrackerTool(size_t num_bits_)
    : num_bits(num_bits_),
      void_type(nullptr),
      taint_type(nullptr),
      intptr_type(nullptr),
      func(nullptr),
      module(nullptr),
      context(nullptr) {}

TaintTrackerTool::~TaintTrackerTool(void) {}

// Called when lifted bitcode or the runtime needs to resolve an external
// symbol.
uint64_t TaintTrackerTool::FindSymbolForLinking(
    const std::string &name, uint64_t resolved) {

  auto c_name = name.c_str();
  if (c_name == strstr(c_name, "__taint")) {
    return reinterpret_cast<uintptr_t>(ReturnUntainted);
  }

  return resolved;
}

// Instrument the runtime module.
bool TaintTrackerTool::InstrumentRuntime(llvm::Module *module_) {
  module = module_;
  context = &(module->getContext());
  void_type = llvm::Type::getVoidTy(*context);
  taint_type = llvm::Type::getIntNTy(*context, num_bits);

  llvm::DataLayout dl(module);
  intptr_type = llvm::Type::getIntNTy(*context, dl.getPointerSizeInBits());

  for (auto &runtime_func : *module) {
    func = &runtime_func;
    VisitRuntimeFunction();
  }

  module = nullptr;
  context = nullptr;
  void_type = nullptr;
  taint_type = nullptr;
  intptr_type = nullptr;
  return true;
}

// Instrument a lifted function/trace.
bool TaintTrackerTool::InstrumentTrace(llvm::Function *func_, uint64_t pc) {
  func = func_;

  if (module != func->getParent()) {
    module = func->getParent();
    context = &(module->getContext());
    void_type = llvm::Type::getVoidTy(*context);
    taint_type = llvm::Type::getIntNTy(*context, num_bits);

    llvm::DataLayout dl(module);
    intptr_type = llvm::Type::getIntNTy(*context, dl.getPointerSizeInBits());
  }

  VisitLiftedFunction();
  return true;
}

void TaintTrackerTool::VisitRuntimeFunction(void) {
  if (!func->isDeclaration()) {
    VisitFunction(func);
  }
}

void TaintTrackerTool::VisitLiftedFunction(void) {
  VisitFunction(func);
}

// Unfold constant expressions into instructions so that we can accumulate
// the taint information of the constants.
void TaintTrackerTool::UnfoldConstantExpressions(llvm::Instruction *inst) {
  for (llvm::Use &op : inst->operands()) {
    auto val = op.get();
    if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
      auto ce_inst = ce->getAsInstruction();
      ce_inst->insertBefore(inst);
      op.set(ce_inst);

      UnfoldConstantExpressions(ce_inst);

      if (!ce->hasNUsesOrMore(1)) {
        ce->destroyConstant();
      }
    }
  }
}

// Expand a GetElementPtrInst into several other instructions.
void TaintTrackerTool::ExpandGEP(llvm::GetElementPtrInst *inst) {
  llvm::DataLayout dl(module);
  llvm::APInt offset(64, 0, true);
  llvm::IRBuilder<> ir(inst);
  auto addr = ir.CreatePtrToInt(inst->getPointerOperand(), intptr_type);

  // Convenient case, the indexes of this GEP are all constant integers.
  if (inst->accumulateConstantOffset(dl, offset)) {
    auto offset_int = offset.getSExtValue();
    auto offset_uint = static_cast<uint64_t>(offset_int);
    if (offset_uint) {
      addr = ir.CreateAdd(
          addr, llvm::ConstantInt::get(intptr_type, offset_uint, true));
    }

  // Inconvenient, split this GEP out into smaller operations which can then
  // be individually taint-tracked.
  } else {
    auto it_end = llvm::gep_type_end(inst);
    for (auto it = llvm::gep_type_begin(inst); it != it_end; ++it) {
      auto index = it.getOperand();
      auto element_type = *it;

      if (auto struct_type = llvm::dyn_cast<llvm::StructType>(element_type)) {
        auto ci = llvm::dyn_cast<llvm::ConstantInt>(index);
        auto elem_index = ci->getZExtValue();
        auto layout = dl.getStructLayout(struct_type);
        auto offset = layout->getElementOffset(elem_index);
        addr = ir.CreateAdd(
            addr, llvm::ConstantInt::get(intptr_type, offset, false));
        continue;
      }

      auto indexed_type = it.getIndexedType();

      CHECK(index->getType()->isIntegerTy());
      if (index->getType() != intptr_type) {
        index = ir.CreateSExt(index, intptr_type);
      }

      auto type_size = dl.getTypeAllocSize(indexed_type);
      addr = ir.CreateAdd(
          addr,
          ir.CreateMul(
              index, llvm::ConstantInt::get(intptr_type, type_size, false)));
    }
  }

  auto ptr = ir.CreateIntToPtr(addr, inst->getType());
  inst->replaceAllUsesWith(ptr);
  inst->eraseFromParent();
}

void TaintTrackerTool::VisitFunction(llvm::Function *func) {
  DCHECK(taint_type != nullptr);
  CHECK(!func->isDeclaration());

  std::vector<llvm::Instruction *> insts;

  auto &context = func->getContext();
  auto entry_block = &(func->getEntryBlock());
  auto taint_block = llvm::BasicBlock::Create(context, "taints",
                                              func, entry_block);
  auto int32_type = llvm::Type::getInt32Ty(context);
  auto arg_taint_func = GetFunc(taint_type, "__taint_load_arg", int32_type);

  llvm::DataLayout dl(module);
  llvm::IRBuilder<> ir(taint_block);

  func_taints.clear();

  // Create taint locations for each function argument.
  unsigned arg_index = 0;
  for (auto &arg : func->args()) {
    auto arg_taint = ir.CreateAlloca(taint_type);
    auto arg_num = llvm::ConstantInt::get(int32_type, arg_index++);
    func_taints[&arg] = arg_taint;
    ir.CreateStore(
        ir.CreateCall(arg_taint_func, {arg_num}),
        arg_taint);
  }

  std::vector<llvm::GetElementPtrInst *> geps;

  for (auto &block : *func) {
    if (&block == taint_block) {
      continue;
    }

    geps.clear();

    for (auto &inst : block) {

      // Unfold any constant expressions in the operand list of an instruction
      // into individual instructions that can be taint tracked.
      UnfoldConstantExpressions(&inst);

      if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(&inst)) {
        geps.push_back(gep_inst);
      }
    }

    // Expand GEP index lists into a bunch of individual instructions that
    // can be tainted.
    for (auto gep : geps) {
      ExpandGEP(gep);
    }

    // We have now fully "expanded" out instructions in this block.
    for (auto &inst : block) {
      func_taints[&inst] = ir.CreateAlloca(taint_type);
      insts.push_back(&inst);
    }
  }

  ir.CreateBr(entry_block);

  for (auto inst : insts) {
    visit(inst);
  }
//
//  func->dump();

//  for (auto inst : insts) {
//    if (!inst->getParent()) {
//      delete inst;
//    }
//  }
}

// Load the taint associated with some value.
llvm::Value *TaintTrackerTool::LoadTaint(llvm::IRBuilder<> &ir,
                                         llvm::Value *val) {

  // The taint of an instruction is stored in an `alloca`.
  if (auto inst = llvm::dyn_cast<llvm::Instruction>(val)) {
    CHECK(inst->getParent()->getParent() == ir.GetInsertBlock()->getParent());
    return ir.CreateLoad(func_taints[inst]);

  // Argument to the current function.
  } else if (auto arg = llvm::dyn_cast<llvm::Argument>(val)) {
    CHECK(arg->getParent() == ir.GetInsertBlock()->getParent());
    return ir.CreateLoad(func_taints[arg]);

  // The taint of a constant is the result of a call to something like
  // `__taint_constant_i8(val)`.
  } else if (llvm::isa<llvm::ConstantInt>(val) ||
             llvm::isa<llvm::ConstantFP>(val)) {

    std::stringstream ss;
    ss << "__taint_const_" << remill::LLVMThingToString(val->getType());
    auto name = ss.str();
    auto taint_func = GetPureFunc(taint_type, name, val->getType());
    return ir.CreateCall(taint_func, {val});

  // The taint of a global variable is the `__taint_global(addr, size)`, where
  // `addr` is the address of the global variable, and `size` is the size in
  // bytes of the data pointed to by `addr`.
  //
  // TODO(pag): These taints should really be initialized once, globally.
  } else if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    llvm::DataLayout dl(module);
    auto taint_func = GetPureFunc(taint_type, "__taint_global",
                                  intptr_type, intptr_type);
    auto val_type = gv->getType()->getElementType();

    std::vector<llvm::Value *> args = {
        ir.CreatePtrToInt(gv, intptr_type),
        llvm::ConstantInt::get(intptr_type, dl.getTypeAllocSize(val_type))
    };
    return ir.CreateCall(taint_func, args);

  // Functions don't really need to be tainted, they can't be changed or
  // indexed into.
  } else if (llvm::isa<llvm::Function>(val)) {
    return llvm::Constant::getNullValue(taint_type);

  // Some kind of constant.
  } else if (auto cv = llvm::dyn_cast<llvm::Constant>(val)) {
    if (cv->isNullValue()) {
      return llvm::Constant::getNullValue(taint_type);
    }

    if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
      if (llvm::Instruction::PtrToInt == ce->getOpcode()) {
        if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(ce->getOperand(0))) {
          llvm::DataLayout dl(module);
          auto taint_func = GetPureFunc(taint_type, "__taint_global",
                                        intptr_type, intptr_type);
          auto val_type = gv->getType()->getElementType();

          std::vector<llvm::Value *> args = {
              ir.CreatePtrToInt(gv, intptr_type),
              llvm::ConstantInt::get(intptr_type, dl.getTypeAllocSize(val_type))
          };
          return ir.CreateCall(taint_func, args);
        }
      }
    }

    LOG(ERROR)
        << "Can't load taint for constant " << remill::LLVMThingToString(cv);
    return llvm::Constant::getNullValue(taint_type);

  // Something else, not sure what.
  } else {
    LOG(ERROR)
        << "Can't load taint for " << remill::LLVMThingToString(val);
    return llvm::Constant::getNullValue(taint_type);
  }
}

// Set up the taints for allocas, which in this case mean, the taint on
// the *address* of the stack-allocated data, not the data itself. The
// taints on the data are handled by load/store and shadow memory.
void TaintTrackerTool::visitAllocaInst(llvm::AllocaInst &inst) {
  llvm::DataLayout dl(module);
  std::stringstream ss;
  auto name = ss.str();
  auto taint_func = GetPureFunc(taint_type, "__taint_local",
                                intptr_type, intptr_type);
  auto val_type = inst.getType()->getElementType();

  llvm::IRBuilder<> ir(&*++inst.getIterator());

  std::vector<llvm::Value *> args = {
      ir.CreatePtrToInt(&inst, intptr_type),
      llvm::ConstantInt::get(intptr_type, dl.getTypeAllocSize(val_type))
  };

  ir.CreateStore(ir.CreateCall(taint_func, args), func_taints[&inst]);
}

void TaintTrackerTool::visitLoadInst(llvm::LoadInst &inst) {
  llvm::DataLayout dl(module);
  std::stringstream ss;
  ss << "__taint_load_" << dl.getTypeAllocSizeInBits(inst.getType());
  auto name = ss.str();
  auto func = GetPureFunc(taint_type, name, intptr_type);
  llvm::IRBuilder<> ir(&inst);
  auto addr = ir.CreatePtrToInt(inst.getPointerOperand(), intptr_type);
  auto taint = ir.CreateCall(func, {addr});
  ir.CreateStore(taint, func_taints[&inst]);
}

void TaintTrackerTool::visitStoreInst(llvm::StoreInst &inst) {
  llvm::DataLayout dl(module);
  std::stringstream ss;
  auto stored_val = inst.getValueOperand();
  auto stored_type = stored_val->getType();
  ss << "__taint_store_" << dl.getTypeAllocSizeInBits(stored_type);
  auto name = ss.str();
  auto func = GetFunc(void_type, name, taint_type, intptr_type);

  llvm::IRBuilder<> ir(&inst);
  auto addr = ir.CreatePtrToInt(inst.getPointerOperand(), intptr_type);
  auto taint = LoadTaint(ir, stored_val);
  std::vector<llvm::Value *> args = {taint, addr};
  (void) ir.CreateCall(func, args);
}

void TaintTrackerTool::visitCastInst(llvm::CastInst &inst) {
  llvm::IRBuilder<> ir(&inst);
  auto taint = LoadTaint(ir, inst.getOperand(0));

  switch (inst.getOpcode()) {
    case llvm::Instruction::Trunc:
    case llvm::Instruction::ZExt:
    case llvm::Instruction::SExt:
    case llvm::Instruction::FPTrunc:
    case llvm::Instruction::FPExt:
    case llvm::Instruction::FPToUI:
    case llvm::Instruction::FPToSI:
    case llvm::Instruction::UIToFP:
    case llvm::Instruction::SIToFP:

    // Size shouldn't change.
    case llvm::Instruction::IntToPtr:
    case llvm::Instruction::PtrToInt:
    case llvm::Instruction::BitCast: {
      ir.CreateStore(taint, func_taints[&inst]);
      break;
    }

    default:
      LOG(ERROR)
          << "Unsupported cast instruction "
          << remill::LLVMThingToString(&inst);
      break;
  }
}

void TaintTrackerTool::visitBinaryOperator(llvm::BinaryOperator &inst) {
  llvm::DataLayout dl(module);
  std::stringstream ss;

  ss << "__taint_binary_" << inst.getOpcodeName() << "_"
     << remill::LLVMThingToString(inst.getType());

  auto name = ss.str();
  auto func = GetPureFunc(taint_type, name, taint_type, taint_type);

  llvm::IRBuilder<> ir(&inst);
  auto lhs = inst.getOperand(0);
  auto rhs = inst.getOperand(1);
  auto lhs_taint = LoadTaint(ir, lhs);
  auto rhs_taint = lhs == rhs ? lhs_taint : LoadTaint(ir, rhs);
  std::vector<llvm::Value *> args = {lhs_taint, rhs_taint};
  ir.CreateStore(ir.CreateCall(func, args), func_taints[&inst]);
}

void TaintTrackerTool::visitCallInst(llvm::CallInst &inst) {

}

void TaintTrackerTool::visitReturnInst(llvm::ReturnInst &inst) {

}

void TaintTrackerTool::visitPHINode(llvm::PHINode &inst) {

}

void TaintTrackerTool::visitSelectInst(llvm::SelectInst &inst) {

}

void TaintTrackerTool::visitBranchInst(llvm::BranchInst &inst) {

}

void TaintTrackerTool::visitIndirectBrInst(llvm::IndirectBrInst &inst) {

}

void TaintTrackerTool::visitSwitchInst(llvm::SwitchInst &inst) {

}

void TaintTrackerTool::visitMemSetInst(llvm::MemSetInst &inst) {

}

void TaintTrackerTool::visitMemCpyInst(llvm::MemCpyInst &inst) {

}

void TaintTrackerTool::visitMemMoveInst(llvm::MemMoveInst &inst) {

}

void TaintTrackerTool::visitMemTransferInst(llvm::MemTransferInst &inst) {

}

}  // namespace vmill
