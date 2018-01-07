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

#include <cstring>
#include <cstdlib>
#include <cinttypes>
#include <string>
#include <sstream>
#include <unordered_set>
#include <vector>

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

#include "tools/TaintTracker/TaintTracker.h"

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

static const uint8_t gZeroStuff[64] = {};

}  // namespace

TaintTrackerTool::TaintTrackerTool(size_t num_bits_)
    : num_bits(num_bits_),
      void_type(nullptr),
      taint_type(nullptr),
      intptr_type(nullptr),
      int32_type(nullptr),
      taint_block(nullptr),
      func(nullptr),
      module(nullptr),
      context(nullptr) {}

TaintTrackerTool::~TaintTrackerTool(void) {}

uintptr_t TaintTrackerTool::FindIntConstantTaint(uint64_t const_val) {
  return reinterpret_cast<uintptr_t>(&(gZeroStuff[0]));
}

uintptr_t TaintTrackerTool::FindFloatConstantTaint(float const_val) {
  return reinterpret_cast<uintptr_t>(&(gZeroStuff[0]));
}

uintptr_t TaintTrackerTool::FindDoubleConstantTaint(double const_val) {
  return reinterpret_cast<uintptr_t>(&(gZeroStuff[0]));
}

uintptr_t TaintTrackerTool::FindTaintTransferFunc(const std::string &name) {
  return reinterpret_cast<uintptr_t>(ReturnUntainted);
}

// Called when lifted bitcode or the runtime needs to resolve an external
// symbol.
uint64_t TaintTrackerTool::FindSymbolForLinking(
    const std::string &name, uint64_t resolved) {

  auto c_name = name.c_str();
  if (c_name != strstr(c_name, "__taint")) {
    return Tool::FindSymbolForLinking(name, resolved);

  // Deal with tainted constants.
  } else if (c_name == strstr(c_name, "__tainted_")) {
    auto &addr = tainted_consts[name];
    if (!addr) {
      if (c_name == strstr(c_name, "__tainted_float_")) {
        uint32_t val = 0;
        CHECK(1 == sscanf(c_name, "__tainted_float_%" SCNx32, &val));
        addr = FindFloatConstantTaint(reinterpret_cast<float &>(val));

      } else if (c_name == strstr(c_name, "__tainted_double_")) {
        uint64_t val = 0;
        CHECK(1 == sscanf(c_name, "__tainted_double_%" SCNx64, &val));
        addr = FindDoubleConstantTaint(reinterpret_cast<double &>(val));

      } else if (c_name == strstr(c_name, "__tainted_int_")) {
        uint64_t val = 0;
        CHECK(1 == sscanf(c_name, "__tainted_int_%" SCNx64, &val));
        addr = FindIntConstantTaint(val);
      }
    }

    if (addr) {
      return addr;
    }

    addr = Tool::FindSymbolForLinking(name, resolved);
    if (addr) {
      return addr;
    }

    LOG(ERROR)
        << "Missing taint symbol " << name << " for immediate constant";
    addr = reinterpret_cast<uintptr_t>(&(gZeroStuff[0]));
    return addr;

  // Deal with taint transfer functions.
  } else {
    auto &addr = tainted_funcs[name];
    if (addr) {
      return addr;
    }

    addr = FindTaintTransferFunc(name);
    if (addr) {
      return addr;
    }

    addr = Tool::FindSymbolForLinking(name, resolved);
    if (addr) {
      return addr;
    }

    LOG(ERROR)
        << "Missing address for taint transfer function " << name;
    addr = reinterpret_cast<uintptr_t>(ReturnUntainted);
    return addr;
  }
}

// Instrument the runtime module.
bool TaintTrackerTool::InstrumentRuntime(llvm::Module *module_) {
  module = module_;
  context = &(module->getContext());
  void_type = llvm::Type::getVoidTy(*context);
  taint_type = llvm::Type::getIntNTy(*context, num_bits);
  int32_type = llvm::Type::getInt32Ty(*context);

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
    int32_type = llvm::Type::getInt32Ty(*context);

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

// Get a taint function.
llvm::Constant *TaintTrackerTool::GetFunc(
    llvm::Type *ret_type, const std::string &name,
    const std::vector<llvm::Type *> &arg_types) {
  auto func_type = llvm::FunctionType::get(ret_type, arg_types, false);
  return module->getOrInsertFunction(name, func_type);
}

// Get a pure taint function, i.e. one that neither reads nor writes to
// memory.
llvm::Constant *TaintTrackerTool::GetPureFunc(
    llvm::Type *ret_type, const std::string &name,
    const std::vector<llvm::Type *> &arg_types) {
  auto func_ = GetFunc(ret_type, name, arg_types);
  if (auto func = llvm::dyn_cast<llvm::Function>(func_)) {
    func->addFnAttr(llvm::Attribute::ReadNone);
  }
  return func_;
}

// Call one of the taint propagation functions.
llvm::Value *TaintTrackerTool::CallFunc(
    llvm::IRBuilder<> &ir, llvm::Constant *func,
    std::vector<llvm::Value *> &params) {
  return ir.CreateCall(func, params);
}

int TaintTrackerTool::UnfoldConstantExpressions(llvm::Instruction *inst,
                                                llvm::Use &use) {
  auto val = use.get();
  if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
    auto ce_inst = ce->getAsInstruction();
    ce_inst->insertBefore(inst);
    auto ret = UnfoldConstantExpressions(ce_inst);
    use.set(ce_inst);
    return ret + 1;
  } else {
    return 0;
  }
}

// Unfold constant expressions into instructions so that we can accumulate
// the taint information of the constants.
int TaintTrackerTool::UnfoldConstantExpressions(llvm::Instruction *inst) {
  int ret = 0;
  for (auto &use : inst->operands()) {
    ret += UnfoldConstantExpressions(inst, use);
  }
  if (auto call = llvm::dyn_cast<llvm::CallInst>(inst)) {
    for (auto &use : call->arg_operands()) {
      ret += UnfoldConstantExpressions(inst, use);
    }
  }
  return ret;
}

// Expand a GetElementPtrInst into several other instructions.
void TaintTrackerTool::ExpandGEP(llvm::GetElementPtrInst *inst) {
  llvm::DataLayout dl(module);
  llvm::APInt offset(64, 0, true);
  llvm::IRBuilder<> ir(inst);

  llvm::Value *addr = nullptr;
  llvm::Value *ptr = nullptr;

  auto base = inst->getPointerOperand()->stripPointerCasts();

  // Try to do some basic folding here.
  if (auto inttoptr = llvm::dyn_cast<llvm::IntToPtrInst>(base)) {
    addr = inttoptr->getOperand(0);
  } else {
    addr = ir.Insert(new llvm::PtrToIntInst(base, intptr_type));
  }

  // Convenient case, the indexes of this GEP are all constant integers.
  if (inst->accumulateConstantOffset(dl, offset)) {
    auto offset_int = offset.getSExtValue();
    auto offset_uint = static_cast<uint64_t>(offset_int);
    if (offset_uint) {
      addr = ir.Insert(llvm::BinaryOperator::CreateAdd(
          addr, llvm::ConstantInt::get(intptr_type, offset_uint, true)));
      ptr = ir.Insert(new llvm::IntToPtrInst(addr, inst->getType()));

    } else {
      ptr = ir.Insert(new llvm::BitCastInst(base, inst->getType()));
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
    ptr = ir.CreateIntToPtr(addr, inst->getType());
  }

  inst->replaceAllUsesWith(ptr);
}

void TaintTrackerTool::VisitFunction(llvm::Function *func) {
  DCHECK(taint_type != nullptr);
  CHECK(!func->isDeclaration());

  std::vector<llvm::Instruction *> insts;
  auto &context = func->getContext();
  auto entry_block = &(func->getEntryBlock());
  taint_block = llvm::BasicBlock::Create(context, "taints", func, entry_block);
  auto int32_type = llvm::Type::getInt32Ty(context);
  auto arg_taint_func = GetFunc(taint_type, "__taint_load_arg", int32_type);

  llvm::DataLayout dl(module);
  llvm::IRBuilder<> ir(taint_block);

  func_taints.clear();

  auto untainted = llvm::Constant::getNullValue(taint_type);

  // Create taint locations for each function argument.
  unsigned arg_index = 0;
  for (auto &arg : func->args()) {
    auto arg_taint = ir.CreateAlloca(taint_type);
    ir.CreateStore(untainted, arg_taint);

    auto arg_num = llvm::ConstantInt::get(int32_type, arg_index++);
    func_taints[&arg] = arg_taint;
    ir.CreateStore(
        CallFunc(ir, arg_taint_func, arg_num),
        arg_taint);
  };

  std::vector<llvm::GetElementPtrInst *> geps;
  int num_rounds = 0;

  for (auto changed = true; changed; ++num_rounds) {
    changed = false;

    for (auto &block : *func) {
      if (&block == taint_block) {
        continue;
      }

      insts.clear();
      for (auto &inst : block) {
        insts.push_back(&inst);
      }

      // Unfold any constant expressions in the operand list of an instruction
      // into individual instructions that can be taint tracked. This might
      // introduce GEPs.
      for (auto inst : insts) {
        if (0 < UnfoldConstantExpressions(inst)) {
          changed = true;
        }
      }

      // Expand GEPs into either bitcasts or equivalent addressing artihmetic
      // instructions.
      geps.clear();
      for (auto &inst : block) {
        if (auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(&inst)) {
          geps.push_back(gep);
        }
      }

      // Expand GEP index lists into a bunch of individual instructions that
      // can be tainted.
      for (auto gep : geps) {
        ExpandGEP(gep);
        gep->eraseFromParent();
        changed = true;
      }
    }
  }

  insts.clear();

  for (auto &block : *func) {
    if (&block != taint_block) {
      for (auto &inst : block) {
        CHECK(!llvm::isa<llvm::GetElementPtrInst>(inst));

        func_taints[&inst] = ir.CreateAlloca(taint_type);
        insts.push_back(&inst);
      }
    }
  }

  ir.CreateBr(entry_block);

  for (auto inst : insts) {
    visit(inst);
  }
}

// Load the taint associated with some value.
llvm::Value *TaintTrackerTool::LoadTaint(llvm::IRBuilder<> &ir,
                                         llvm::Value *val) {

  // The taint of an instruction is stored in an `alloca`.
  if (auto inst = llvm::dyn_cast<llvm::Instruction>(val)) {
    CHECK(inst->getParent()->getParent() == ir.GetInsertBlock()->getParent());
    auto &taint_alloca = func_taints[inst];
    if (!taint_alloca) {

    }
    return ir.CreateLoad(taint_alloca);

  // Argument to the current function.
  } else if (auto arg = llvm::dyn_cast<llvm::Argument>(val)) {
    CHECK(arg->getParent() == ir.GetInsertBlock()->getParent());
    return ir.CreateLoad(func_taints[arg]);

  // The taint of a constant is the result of a call to something like
  // `__taint_constant_i8(val)`.
  } else if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(val)) {
    std::stringstream ss;
    ss << "__tainted_int_" << std::hex << ci->getZExtValue();
    auto name = ss.str();
    auto global = module->getOrInsertGlobal(name, taint_type);
    return ir.CreateLoad(global);
  }

  auto not_tainted = llvm::Constant::getNullValue(taint_type);

  if (auto cf = llvm::dyn_cast<llvm::ConstantFP>(val)) {
    auto &apf = cf->getValueAPF();

    std::stringstream ss;
    ss << "__tainted_";
    auto type = cf->getType();
    if (type->isFloatTy()) {
      auto fv = apf.convertToFloat();
      ss << "float_" << std::hex << reinterpret_cast<uint32_t &>(fv);

    } else if (type->isDoubleTy()) {
      auto dv = apf.convertToDouble();
      ss << "double_" << std::hex << reinterpret_cast<uint64_t &>(dv);

    } else {
      LOG(ERROR)
          << "Can't taint constant of type " << remill::LLVMThingToString(type);
      return not_tainted;
    }

    auto name = ss.str();
    auto global = module->getOrInsertGlobal(name, taint_type);
    return ir.CreateLoad(global);

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
    return CallFunc(
        ir, taint_func, ir.CreatePtrToInt(gv, intptr_type),
        llvm::ConstantInt::get(intptr_type, dl.getTypeAllocSize(val_type)));
  }


  // Functions don't really need to be tainted, they can't be changed or
  // indexed into.
  if (llvm::isa<llvm::Function>(val)) {
    return not_tainted;

  // Probably from the runtime.
  } else if (llvm::isa<llvm::UndefValue>(val)) {
    return not_tainted;

  // Some kind of constant.
  } else if (auto cv = llvm::dyn_cast<llvm::Constant>(val)) {
    if (cv->isNullValue()) {
      return not_tainted;
    }

    auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val);
    if (!ce) {
      LOG(ERROR)
          << "Can't load taint for constant " << remill::LLVMThingToString(cv);
      return not_tainted;
    }

    // If it's a global, basted to an integer, then lets use that and
    // treat is like we treat other such taints.
    if (llvm::Instruction::PtrToInt == ce->getOpcode() ||
        llvm::Instruction::IntToPtr == ce->getOpcode()) {
      auto base = ce->getOperand(0)->stripPointerCasts();
      return LoadTaint(ir, base);

    // Hopefully it's a zero-index GEP.
    } else if (llvm::Instruction::GetElementPtr == ce->getOpcode()) {
      auto base = ce->stripPointerCasts();
      if (base != ce) {
        return LoadTaint(ir, base);
      }
    }

    LOG(ERROR)
        << "Can't load taint for constant " << remill::LLVMThingToString(cv);
    return not_tainted;

  // Something else, not sure what.
  } else {
    LOG(ERROR)
        << "Can't load taint for " << remill::LLVMThingToString(val);
    return not_tainted;
  }
}

// Set up the taints for allocas, which in this case mean, the taint on
// the *address* of the stack-allocated data, not the data itself. The
// taints on the data are handled by load/store and shadow memory.
void TaintTrackerTool::visitAllocaInst(llvm::AllocaInst &inst) {
  llvm::IRBuilder<> ir(&*++inst.getIterator());
  llvm::DataLayout dl(module);
  std::stringstream ss;
  auto name = ss.str();
  auto taint_func = GetPureFunc(taint_type, "__taint_local",
                                intptr_type, intptr_type);
  auto val_type = inst.getType()->getElementType();
  auto alloca_size = dl.getTypeAllocSize(val_type);
  auto alloca_taint = CallFunc(
      ir, taint_func, ir.CreatePtrToInt(&inst, intptr_type),
      llvm::ConstantInt::get(intptr_type, alloca_size));
  ir.CreateStore(alloca_taint, func_taints[&inst]);
}

void TaintTrackerTool::visitLoadInst(llvm::LoadInst &inst) {
  llvm::DataLayout dl(module);
  std::stringstream ss;
  ss << "__taint_load_" << dl.getTypeAllocSizeInBits(inst.getType());
  auto name = ss.str();
  auto func = GetPureFunc(taint_type, name, taint_type, intptr_type);
  llvm::IRBuilder<> ir(&inst);
  auto addr = inst.getPointerOperand();
  auto addr_taint = LoadTaint(ir, addr);
  auto taint = CallFunc(ir, func, addr_taint,
                        ir.CreatePtrToInt(addr, intptr_type));
  ir.CreateStore(taint, func_taints[&inst]);
}

void TaintTrackerTool::visitStoreInst(llvm::StoreInst &inst) {
  llvm::DataLayout dl(module);
  std::stringstream ss;
  auto stored_val = inst.getValueOperand();
  auto stored_type = stored_val->getType();
  ss << "__taint_store_" << dl.getTypeAllocSizeInBits(stored_type);
  auto name = ss.str();
  auto func = GetFunc(void_type, name, taint_type, intptr_type, taint_type);

  llvm::IRBuilder<> ir(&inst);
  auto addr = inst.getPointerOperand();
  auto addr_taint = LoadTaint(ir, addr);
  auto taint = LoadTaint(ir, stored_val);
  (void) CallFunc(ir, func, addr_taint, ir.CreatePtrToInt(addr, intptr_type),
                  taint);
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
    case llvm::Instruction::SIToFP: {
      std::stringstream ss;
      ss << "__taint_" << inst.getOpcodeName() << "_to_"
         << remill::LLVMThingToString(inst.getType());
      auto name = ss.str();
      auto func = GetPureFunc(taint_type, name, taint_type);
      auto conv_taint = CallFunc(ir, func, taint);
      ir.CreateStore(conv_taint, func_taints[&inst]);
      break;
    }

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

  ss << "__taint_" << inst.getOpcodeName() << "_"
     << remill::LLVMThingToString(inst.getType());

  auto name = ss.str();
  auto func = GetPureFunc(taint_type, name, taint_type, taint_type);

  llvm::IRBuilder<> ir(&inst);
  auto lhs = inst.getOperand(0);
  auto rhs = inst.getOperand(1);
  auto lhs_taint = LoadTaint(ir, lhs);
  auto rhs_taint = lhs == rhs ? lhs_taint : LoadTaint(ir, rhs);
  std::vector<llvm::Value *> args = {lhs_taint, rhs_taint};
  ir.CreateStore(CallFunc(ir, func, lhs_taint, rhs_taint), func_taints[&inst]);
}

namespace {

static const char *GetPredicateName(llvm::CmpInst &inst) {
  switch (inst.getPredicate()) {
    case llvm::FCmpInst::FCMP_FALSE: return "false";
    case llvm::FCmpInst::FCMP_OEQ: return "oeq";
    case llvm::FCmpInst::FCMP_OGT: return "ogt";
    case llvm::FCmpInst::FCMP_OGE: return "oge";
    case llvm::FCmpInst::FCMP_OLT: return "olt";
    case llvm::FCmpInst::FCMP_OLE: return "ole";
    case llvm::FCmpInst::FCMP_ONE: return "one";
    case llvm::FCmpInst::FCMP_ORD: return "ord";
    case llvm::FCmpInst::FCMP_UNO: return "uno";
    case llvm::FCmpInst::FCMP_UEQ: return "ueq";
    case llvm::FCmpInst::FCMP_UGT: return "ugt";
    case llvm::FCmpInst::FCMP_UGE: return "uge";
    case llvm::FCmpInst::FCMP_ULT: return "ult";
    case llvm::FCmpInst::FCMP_ULE: return "ule";
    case llvm::FCmpInst::FCMP_UNE: return "une";
    case llvm::FCmpInst::FCMP_TRUE: return "true";
    case llvm::ICmpInst::ICMP_EQ: return "eq";
    case llvm::ICmpInst::ICMP_NE: return "ne";
    case llvm::ICmpInst::ICMP_SGT: return "sgt";
    case llvm::ICmpInst::ICMP_SGE: return "sge";
    case llvm::ICmpInst::ICMP_SLT: return "slt";
    case llvm::ICmpInst::ICMP_SLE: return "sle";
    case llvm::ICmpInst::ICMP_UGT: return "ugt";
    case llvm::ICmpInst::ICMP_UGE: return "uge";
    case llvm::ICmpInst::ICMP_ULT: return "ult";
    case llvm::ICmpInst::ICMP_ULE: return "ule";
    default: return "unknown";
  }
}

}  // namespace

void TaintTrackerTool::visitCmpInst(llvm::CmpInst &inst) {
  llvm::DataLayout dl(module);
  std::stringstream ss;

  auto cmp_type = inst.getOperand(0)->getType();
  if (cmp_type->isPointerTy()) {
    cmp_type = llvm::Type::getIntNTy(*context, dl.getPointerSizeInBits(0));
  }

  ss << "__taint_" << inst.getOpcodeName() << "_" << GetPredicateName(inst)
     << "_" << remill::LLVMThingToString(cmp_type);

  auto name = ss.str();
  auto func = GetPureFunc(taint_type, name, taint_type, taint_type);

  llvm::IRBuilder<> ir(&inst);
  auto lhs = inst.getOperand(0);
  auto rhs = inst.getOperand(1);
  auto lhs_taint = LoadTaint(ir, lhs);
  auto rhs_taint = lhs == rhs ? lhs_taint : LoadTaint(ir, rhs);
  ir.CreateStore(CallFunc(ir, func, lhs_taint, rhs_taint), func_taints[&inst]);
}

void TaintTrackerTool::visitGetElementPtrInst(llvm::GetElementPtrInst &inst) {
  llvm::DataLayout dl(module);
  llvm::APInt offset(64, 0, true);
  llvm::IRBuilder<> ir(&inst);

  auto base = inst.getPointerOperand()->stripPointerCasts();
  llvm::Value *taint = llvm::Constant::getNullValue(taint_type);

  // Convenient case, the indexes of this GEP are all constant integers.
  if (inst.accumulateConstantOffset(dl, offset)) {
    if (offset.getZExtValue()) {
      LOG(ERROR)
          << "Cannot taint GEP instruction: "
          << remill::LLVMThingToString(&inst);

    } else {
      taint = LoadTaint(ir, base);
    }

  // Inconvenient, split this GEP out into smaller operations which can then
  // be individually taint-tracked.
  } else {
    LOG(ERROR)
        << "Cannot taint GEP instruction: " << remill::LLVMThingToString(&inst);
  }

  ir.CreateStore(taint, func_taints[&inst]);
}

void TaintTrackerTool::visitIntrinsicInst(llvm::IntrinsicInst &inst) {
  std::vector<llvm::Value *> args;
  std::vector<llvm::Type *> arg_types;
  llvm::IRBuilder<> ir(&inst);
  for (unsigned i = 0; i < inst.getNumArgOperands(); ++i) {
    auto arg = inst.getArgOperand(i);
    auto taint_arg = LoadTaint(ir, arg);
    args.push_back(taint_arg);
    arg_types.push_back(taint_type);
  }

  auto intrinsic_name = llvm::Intrinsic::getName(inst.getIntrinsicID());

  std::stringstream ss;
  ss << "__taint_";
  for (auto c : intrinsic_name) {
    if (isalnum(c)) {
      ss << c;
    } else {
      ss << '_';
    }
  }

  auto ret_type = inst.getType();
  if (!ret_type->isVoidTy()) {
    ss << "_" << remill::LLVMThingToString(ret_type);
  }

  auto name = ss.str();

  if (inst.getType() == void_type) {
    auto taint_func = GetFunc(void_type, name, arg_types);
    (void) CallFunc(ir, taint_func, args);
  } else {
    auto taint_func = GetPureFunc(taint_type, name, arg_types);
    auto taint = CallFunc(ir, taint_func, args);
    ir.CreateStore(taint, func_taints[&inst]);
  }
}

void TaintTrackerTool::visitCallInst(llvm::CallInst &inst) {
  auto called_val = inst.getCalledValue();

  llvm::IRBuilder<> ir(&inst);

  // Don't try to pass taints for varargs functions or to inline assembly.
  if (llvm::isa<llvm::InlineAsm>(called_val)) {
    ir.CreateStore(llvm::Constant::getNullValue(taint_type),
                   func_taints[&inst]);
    return;
  }

  auto taint_func = GetFunc(void_type, "__taint_store_arg", int32_type,
                            taint_type);

  unsigned i = 0;
  for (auto &arg : inst.arg_operands()) {
    CallFunc(ir, taint_func, llvm::ConstantInt::get(int32_type, i++),
             LoadTaint(ir, arg.get()));
  }

  if (func->getReturnType() != void_type) {
    taint_func = GetFunc(taint_type, "__taint_load_ret");
    ir.SetInsertPoint(&*++(inst.getIterator()));
    ir.CreateStore(CallFunc(ir, taint_func), func_taints[&inst]);
  }
}

void TaintTrackerTool::visitReturnInst(llvm::ReturnInst &inst) {
  if (auto val = inst.getReturnValue()) {
    auto taint_func = GetFunc(void_type, "__taint_store_ret", taint_type);
    llvm::IRBuilder<> ir(&inst);
    CallFunc(ir, taint_func, LoadTaint(ir, val));
  }
}

// Forwards the taints from the source block to the phi node.
void TaintTrackerTool::visitPHINode(llvm::PHINode &inst) {
  for (auto &op : inst.operands()) {
    auto block = inst.getIncomingBlock(op);
    auto val = op.get();
    llvm::IRBuilder<> ir(block->getTerminator());
    ir.CreateStore(LoadTaint(ir, val), func_taints[&inst]);
  }
}

void TaintTrackerTool::visitSelectInst(llvm::SelectInst &inst) {
  auto cond = inst.getCondition();
  auto cond_type = cond->getType();
  if (llvm::isa<llvm::VectorType>(cond_type)) {
    LOG(ERROR)
        << "Taint tracking of vector-based selects is not yet supported.";
    return;
  }
  llvm::IRBuilder<> ir(&inst);
  auto taint_func = GetPureFunc(taint_type, "__taint_select",
                                taint_type, cond_type, taint_type, taint_type);

  auto select_taint = CallFunc(ir, taint_func, LoadTaint(ir, cond), cond,
                               LoadTaint(ir, inst.getTrueValue()),
                               LoadTaint(ir, inst.getFalseValue()));
  ir.CreateStore(select_taint, func_taints[&inst]);
}

void TaintTrackerTool::visitBranchInst(llvm::BranchInst &inst) {
  if (inst.isUnconditional()) {
    return;
  }

  auto cond = inst.getCondition();
  auto bool_type = llvm::Type::getInt1Ty(*context);
  CHECK(bool_type == cond->getType());
  auto taint_func = GetFunc(void_type, "__taint_branch",
                            taint_type, bool_type);
  llvm::IRBuilder<> ir(&inst);
  (void) CallFunc(ir, taint_func, LoadTaint(ir, cond), cond);
}

void TaintTrackerTool::visitIndirectBrInst(llvm::IndirectBrInst &inst) {
  LOG(ERROR)
      << "Indirect branches not yet handled: "
      << remill::LLVMThingToString(&inst);
}

void TaintTrackerTool::visitSwitchInst(llvm::SwitchInst &inst) {
  auto cond = inst.getCondition();

  std::vector<uint64_t> vals;
  for (auto &case_entry : inst.cases()) {
    auto case_val = case_entry.getCaseValue()->getZExtValue();
    vals.push_back(case_val);
  }

  auto int64_type = llvm::Type::getInt64Ty(*context);
  auto int64_ptr_type = llvm::PointerType::get(int64_type, 0);
  auto cases = llvm::ConstantDataArray::get(*context, vals);
  auto case_array = new llvm::GlobalVariable(
      *module, cases->getType(), true, llvm::GlobalValue::PrivateLinkage,
      cases);

  auto first_entry = llvm::ConstantExpr::getGetElementPtr(
      int64_type, case_array, llvm::ConstantInt::get(intptr_type, 0));
  auto after_last_entry = llvm::ConstantExpr::getGetElementPtr(
      int64_type, case_array, llvm::ConstantInt::get(intptr_type, 1));

  auto taint_func = GetFunc(void_type, "__taint_switch",
                            taint_type, int64_type, int64_ptr_type,
                            int64_ptr_type);
  llvm::IRBuilder<> ir(&inst);
  (void) CallFunc(ir, taint_func, LoadTaint(ir, cond),
                  ir.CreateZExt(cond, int64_type),
                  first_entry, after_last_entry);
}

void TaintTrackerTool::visitExtractElementInst(llvm::ExtractElementInst &inst) {
  LOG(ERROR)
      << "Unsupported " << remill::LLVMThingToString(&inst);

  auto not_tainted = llvm::Constant::getNullValue(taint_type);
  llvm::IRBuilder<> ir(&inst);
  ir.CreateStore(not_tainted, func_taints[&inst]);
}

void TaintTrackerTool::visitInsertElementInst(llvm::InsertElementInst &inst) {
  LOG(ERROR)
      << "Unsupported " << remill::LLVMThingToString(&inst);

  auto not_tainted = llvm::Constant::getNullValue(taint_type);
  llvm::IRBuilder<> ir(&inst);
  ir.CreateStore(not_tainted, func_taints[&inst]);
}

void TaintTrackerTool::visitMemSetInst(llvm::MemSetInst &inst) {
  llvm::IRBuilder<> ir(&inst);
  auto taint_addr = LoadTaint(ir, inst.getDest());
  auto taint_length = LoadTaint(ir, inst.getLength());
  auto taint_val = LoadTaint(ir, inst.getValue());

  auto addr = ir.CreatePtrToInt(inst.getDest(), intptr_type);
  auto length = ir.CreateZExt(inst.getLength(), intptr_type);
  auto val = ir.CreateZExt(inst.getValue(), intptr_type);

  auto taint_func = GetFunc(
      void_type, "__taint_memset",
      taint_type, intptr_type,  // Destination address.
      taint_type, intptr_type,  // Value.
      taint_type, intptr_type); // Destination size.

  (void) CallFunc(ir, taint_func, taint_addr, addr,
                  taint_val, val, taint_length, length);
}

void TaintTrackerTool::visitMemCpyInst(llvm::MemCpyInst &inst) {
  llvm::IRBuilder<> ir(&inst);
  auto taint_dest_addr = LoadTaint(ir, inst.getDest());
  auto taint_src_addr = LoadTaint(ir, inst.getSource());
  auto taint_length = LoadTaint(ir, inst.getLength());

  auto dest_addr = ir.CreatePtrToInt(inst.getDest(), intptr_type);
  auto src_addr = ir.CreatePtrToInt(inst.getSource(), intptr_type);
  auto length = ir.CreateZExt(inst.getLength(), intptr_type);

  auto taint_func = GetFunc(
      void_type, "__taint_memcpy",
      taint_type, intptr_type,  // Destination address.
      taint_type, intptr_type,  // Source address.
      taint_type, intptr_type); // Destination size.

  (void) CallFunc(ir, taint_func, taint_dest_addr, dest_addr,
                  taint_src_addr, src_addr, taint_length, length);
}

void TaintTrackerTool::visitMemMoveInst(llvm::MemMoveInst &inst) {
  llvm::IRBuilder<> ir(&inst);
  auto taint_dest_addr = LoadTaint(ir, inst.getDest());
  auto taint_src_addr = LoadTaint(ir, inst.getSource());
  auto taint_length = LoadTaint(ir, inst.getLength());

  auto dest_addr = ir.CreatePtrToInt(inst.getDest(), intptr_type);
  auto src_addr = ir.CreatePtrToInt(inst.getSource(), intptr_type);
  auto length = ir.CreateZExt(inst.getLength(), intptr_type);

  auto taint_func = GetFunc(
      void_type, "__taint_memmove",
      taint_type, intptr_type,  // Destination address.
      taint_type, intptr_type,  // Source address.
      taint_type, intptr_type); // Destination size.

  (void) CallFunc(ir, taint_func, taint_dest_addr, dest_addr,
                  taint_src_addr, src_addr, taint_length, length);
}

}  // namespace vmill
