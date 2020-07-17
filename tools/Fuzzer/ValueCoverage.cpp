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

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <remill/BC/Version.h>
#include <remill/OS/FileSystem.h>
#include <remill/OS/OS.h>

#include "vmill/Program/ShadowMemory.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Workspace/Workspace.h"

#include "tools/Fuzzer/Fuzzer.h"
#include "tools/Fuzzer/Location.h"

namespace vmill {
namespace {

static void DummyCoverCompare1(Location, int predicate, uint8_t, uint8_t) {}
static void DummyCoverCompare2(Location, int predicate, uint16_t, uint16_t) {}
static void DummyCoverCompare4(Location, int predicate, uint32_t, uint32_t) {}
static void DummyCoverCompare8(Location, int predicate, uint64_t, uint64_t) {}

// Instruments the code so that a fuzzer can observe comparisons between
// values. This is kind of like `-fsanitize=trace-cmp`.
class ValueCoverageTool : public Tool, public PersistentLocation {
 public:
  ValueCoverageTool(void)
      : PersistentLocation(kLocationTypeValue),
        module(nullptr),
        dl(""),
        loc_type(nullptr),
        int8_type(nullptr),
        int16_type(nullptr),
        int32_type(nullptr),
        int64_type(nullptr),
        cov_cmp_1_func(nullptr),
        cov_cmp_2_func(nullptr),
        cov_cmp_4_func(nullptr),
        cov_cmp_8_func(nullptr) {

    OfferSymbol("__cov_cmp_1", DummyCoverCompare1);
    OfferSymbol("__cov_cmp_2", DummyCoverCompare2);
    OfferSymbol("__cov_cmp_4", DummyCoverCompare4);
    OfferSymbol("__cov_cmp_8", DummyCoverCompare8);
  }

  virtual ~ValueCoverageTool(void) {}

  // Instrument the runtime module.
  bool InstrumentRuntime(llvm::Module *module) final {
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

    std::vector<llvm::CmpInst *> compares;

    for (auto &block : *func) {
      for (auto &inst : block) {
        if (auto cmp = llvm::dyn_cast<llvm::CmpInst>(&inst)) {
          compares.push_back(cmp);
        }
      }
    }

    for (auto inst : compares) {
      Instrument(inst);
    }

    return true;
  }

  void PrepareModule(llvm::Module *module_) override {
    module = module_;
    dl.init(module);

    auto &context = module->getContext();
    auto void_type = llvm::Type::getVoidTy(context);

    int8_type = llvm::Type::getInt8Ty(context);
    int16_type = llvm::Type::getInt16Ty(context);
    int32_type = llvm::Type::getInt32Ty(context);
    int64_type = llvm::Type::getInt64Ty(context);
    loc_type = llvm::Type::getIntNTy(context, sizeof(Location) * 8);

    llvm::Type *cmp_1_args[] = {loc_type, int32_type, int8_type, int8_type};
    cov_cmp_1_func = llvm::dyn_cast<llvm::Function>(
        module->getOrInsertFunction(
            "__cov_cmp_1", llvm::FunctionType::get(void_type, cmp_1_args, false))
        IF_LLVM_GTE_900(.getCallee()));

    llvm::Type *cmp_2_args[] = {loc_type, int32_type, int16_type, int16_type};
    cov_cmp_2_func = llvm::dyn_cast<llvm::Function>(
        module->getOrInsertFunction(
            "__cov_cmp_2", llvm::FunctionType::get(void_type, cmp_2_args, false))
        IF_LLVM_GTE_900(.getCallee()));

    llvm::Type *cmp_4_args[] = {loc_type, int32_type, int32_type, int32_type};
    cov_cmp_4_func = llvm::dyn_cast<llvm::Function>(
        module->getOrInsertFunction(
            "__cov_cmp_4", llvm::FunctionType::get(void_type, cmp_4_args, false))
        IF_LLVM_GTE_900(.getCallee()));

    llvm::Type *cmp_8_args[] = {loc_type, int32_type, int64_type, int64_type};
    cov_cmp_8_func = llvm::dyn_cast<llvm::Function>(
        module->getOrInsertFunction(
            "__cov_cmp_8", llvm::FunctionType::get(void_type, cmp_8_args, false))
        IF_LLVM_GTE_900(.getCallee()));
  }

 private:
  void Instrument(llvm::CmpInst *inst) {
    auto lhs_val = inst->getOperand(0);
    auto rhs_val = inst->getOperand(1);
    auto cmp_type = lhs_val->getType();
    if (cmp_type->isPointerTy()) {
      return;
    }

    llvm::Constant *cmp_func = nullptr;
    llvm::Type *to_type = nullptr;

    auto type_size = dl.getTypeAllocSize(cmp_type);
    switch (type_size) {
      case 1:
        cmp_func = cov_cmp_1_func;
        to_type = int8_type;
        break;
      case 2:
        cmp_func = cov_cmp_2_func;
        to_type = int16_type;
        break;
      case 4:
        cmp_func = cov_cmp_4_func;
        to_type = int32_type;
        break;
      case 8:
        cmp_func = cov_cmp_8_func;
        to_type = int64_type;
        break;
      default:
        return;
    }

    llvm::IRBuilder<> ir(inst);
    if (cmp_type != to_type) {
      if (cmp_type->isIntegerTy()) {
        lhs_val = ir.CreateZExt(lhs_val, to_type);
        rhs_val = ir.CreateZExt(rhs_val, to_type);

      } else if (cmp_type->isFloatTy() || cmp_type->isDoubleTy()) {
        lhs_val = ir.CreateBitCast(lhs_val, to_type);
        rhs_val = ir.CreateBitCast(rhs_val, to_type);

      } else {
        return;
      }
    }
    auto pred = static_cast<unsigned>(inst->getPredicate());

    llvm::Value *args[] = {
        llvm::ConstantInt::get(loc_type, loc++),
        llvm::ConstantInt::get(int32_type, pred),
        lhs_val,
        rhs_val};

    ir.CreateCall(cmp_func, args);
  }

  llvm::Module *module;
  llvm::DataLayout dl;

  llvm::IntegerType *loc_type;

  llvm::IntegerType *int8_type;
  llvm::IntegerType *int16_type;
  llvm::IntegerType *int32_type;
  llvm::IntegerType *int64_type;

  llvm::Constant *cov_cmp_1_func;
  llvm::Constant *cov_cmp_2_func;
  llvm::Constant *cov_cmp_4_func;
  llvm::Constant *cov_cmp_8_func;
};

}  // namespace

std::unique_ptr<Tool> CreateValueCoverageTracker(void) {
  return std::unique_ptr<Tool>(new ValueCoverageTool);
}

}  // namespace vmill
