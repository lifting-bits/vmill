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

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "remill/BC/Version.h"
#include "remill/BC/Util.h"
#include "vmill/BC/Util.h"

namespace vmill {
namespace {

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

  LOG_IF(FATAL, func->hasLocalLinkage())
      << "Cannot declare internal function " << func->getName().str()
      << " as external in another module";

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

  auto type = var->getType()->getElementType();
  dest_var = new llvm::GlobalVariable(
      *dest_module, type, var->isConstant(), var->getLinkage(), nullptr,
      var->getName(), nullptr, var->getThreadLocalMode(),
      var->getType()->getAddressSpace());

  dest_var->copyAttributesFrom(var);

  if (var->hasInitializer() && var->hasLocalLinkage()) {
    auto initializer = var->getInitializer();
#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 6)
    CHECK(!initializer->needsRelocation())
        << "Initializer of global " << var->getName().str()
        << " cannot be trivially copied to the destination module.";
#endif
    dest_var->setInitializer(initializer);
  } else {
    LOG_IF(FATAL, var->hasLocalLinkage())
        << "Cannot declare internal variable " << var->getName().str()
        << " as external in another module";
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

}  // namespace

// Move a function from one module into another module.
void MoveFunctionIntoModule(llvm::Function *func,
                            llvm::Module *dest_module) {
  CHECK(&(func->getContext()) == &(dest_module->getContext()))
      << "Cannot move function across two independent LLVM contexts.";

  auto source_module = func->getParent();
  CHECK(source_module != dest_module)
      << "Cannot move function to the same module.";

  auto existing = dest_module->getFunction(func->getName());
  if (existing) {
    CHECK(existing->isDeclaration())
        << "Function " << func->getName().str()
        << " already exists in destination module.";
    existing->setName("");
    existing->setLinkage(llvm::GlobalValue::PrivateLinkage);
    existing->setVisibility(llvm::GlobalValue::DefaultVisibility);
  }

  func->removeFromParent();
  dest_module->getFunctionList().push_back(func);

  if (existing) {
    existing->replaceAllUsesWith(func);
    existing->eraseFromParent();
    existing = nullptr;
  }

  IF_LLVM_GTE_36( ClearMetaData(func); )

  for (auto &block : *func) {
    for (auto &inst : block) {
      ClearMetaData(&inst);

      // Substitute globals in the operands.
      for (auto &op : inst.operands()) {
        auto old_val = op.get();
        auto used_val = old_val->stripPointerCasts();
        auto used_func = llvm::dyn_cast<llvm::Function>(used_val);
        auto used_var = llvm::dyn_cast<llvm::GlobalVariable>(used_val);
        llvm::Constant *new_val = nullptr;
        if (used_func) {
          new_val = DeclareFunctionInModule(used_func, dest_module);

        } else if (used_var) {
          new_val = DeclareVarInModule(used_var, dest_module);

        } else {
          CHECK(!llvm::isa<llvm::GlobalValue>(used_val))
              << "Cannot move global value " << used_val->getName().str()
              << " into destination module.";
        }

        if (new_val) {
          if (old_val->getType() != new_val->getType()) {
            op.set(llvm::ConstantExpr::getBitCast(new_val, old_val->getType()));
          } else {
            op.set(new_val);
          }
        }
      }
    }
  }
}

}  // namespace vmill
