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

#ifndef TOOLS_TAINT_TAINT_H_
#define TOOLS_TAINT_TAINT_H_

#include <llvm/IR/Function.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include "remill/BC/Compat/Attributes.h"

#include "vmill/Workspace/Tool.h"

#include <unordered_map>

namespace llvm {
class AllocaInst;
class BasicBlock;
class BinaryOperator;
class BranchInst;
class CallInst;
class CastInst;
class GetElementPtrInst;
class IndirectBrInst;
class Instruction;
class IntegerType;
class LoadInst;
class MemIntrinsic;
class PHINode;
class ReturnInst;
class SelectInst;
class StoreInst;
class SwitchInst;
class Value;
class Use;
}  // namespace llvm
namespace vmill {

class TaintTrackerTool : public Tool,
                         public llvm::InstVisitor<TaintTrackerTool> {
 public:
  explicit TaintTrackerTool(size_t num_bits_);

  virtual ~TaintTrackerTool(void);

  virtual uintptr_t FindIntConstantTaint(uint64_t const_val);
  virtual uintptr_t FindFloatConstantTaint(float const_val);
  virtual uintptr_t FindDoubleConstantTaint(double const_val);
  virtual uintptr_t FindTaintTransferFunc(const std::string &name);

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol. This overload is provided so that client tools can choose which
  // specific taint functions they want to override, and aren't required to
  // actually
  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) override;

  // Prepare the module for instrumentation.
  void PrepareModule(llvm::Module *module_) override;

  // Instrument the runtime module.
  bool InstrumentRuntime(llvm::Module *module_) override;

  // Instrument a lifted function/trace.
  bool InstrumentTrace(llvm::Function *func_, uint64_t pc) override;

 private:
  TaintTrackerTool(void) = delete;

  // Get a taint function that is "pure".
  template <typename... ArgTypes>
  inline llvm::Constant *GetPureFunc(llvm::Type *ret_type,
                                     const std::string &name,
                                     ArgTypes... types) {
    std::vector<llvm::Type *> arg_types = {types...};
    return GetPureFunc(ret_type, name, arg_types);
  }

  // Get a taint function.
  template <typename... ArgTypes>
  inline llvm::Constant *GetFunc(llvm::Type *ret_type,
                                 const std::string &name,
                                 ArgTypes... types) {
    std::vector<llvm::Type *> arg_types = {types...};
    return GetFunc(ret_type, name, arg_types);
  }

  // Get a taint function.
  llvm::Constant *GetFunc(llvm::Type *ret_type,
                          const std::string &name,
                          const std::vector<llvm::Type *> &arg_types);


  // Get a pure taint function, i.e. one that neither reads nor writes to
  // memory.
  llvm::Constant *GetPureFunc(llvm::Type *ret_type,
                              const std::string &name,
                              const std::vector<llvm::Type *> &arg_types);

  // Call one of the taint propagation functions.
  template <typename... ArgTypes>
  inline llvm::Value *CallFunc(llvm::IRBuilder<> &ir, llvm::Constant *func,
                               ArgTypes... args) {
    std::vector<llvm::Value *> params = {args...};
    return CallFunc(ir, func, params);
  }

  // Call one of the taint propagation functions.
  llvm::Value *CallFunc(llvm::IRBuilder<> &ir, llvm::Constant *func,
                        std::vector<llvm::Value *> &params);

  int UnfoldConstantExpressions(llvm::Instruction *inst,
                                llvm::Use &use);
  int UnfoldConstantExpressions(llvm::Instruction *inst);
  void ExpandGEP(llvm::GetElementPtrInst *inst);

  void VisitRuntimeFunction(void);
  void VisitLiftedFunction(void);
  void VisitFunction(llvm::Function *func);

 protected:
  friend class llvm::InstVisitor<TaintTrackerTool>;

  // Overrides from the `llvm::InstVisitor`.
  void visitAllocaInst(llvm::AllocaInst &inst);
  void visitLoadInst(llvm::LoadInst &inst);
  void visitStoreInst(llvm::StoreInst &inst);
  void visitIntrinsicInst(llvm::IntrinsicInst &inst);
  void visitGetElementPtrInst(llvm::GetElementPtrInst &inst);
  void visitCallInst(llvm::CallInst &inst);
  void visitReturnInst(llvm::ReturnInst  &inst);
  void visitPHINode(llvm::PHINode  &inst);
  void visitSelectInst(llvm::SelectInst &inst);
  void visitBranchInst(llvm::BranchInst &inst);
  void visitIndirectBrInst(llvm::IndirectBrInst &inst);
  void visitSwitchInst(llvm::SwitchInst &inst);
  void visitCastInst(llvm::CastInst &inst);
  void visitBinaryOperator(llvm::BinaryOperator &inst);
  void visitCmpInst(llvm::CmpInst &inst);
  void visitExtractElementInst(llvm::ExtractElementInst &inst);
  void visitInsertElementInst(llvm::InsertElementInst &inst);
  void visitMemSetInst(llvm::MemSetInst &inst);
  void visitMemCpyInst(llvm::MemCpyInst &inst);
  void visitMemMoveInst(llvm::MemMoveInst &inst);

 private:
  llvm::Value *LoadTaint(llvm::IRBuilder<> &ir, llvm::Value *val);

  size_t num_bits;
  llvm::Type *void_type;
  llvm::IntegerType *taint_type;
  llvm::IntegerType *intptr_type;
  llvm::IntegerType *int32_type;

  llvm::BasicBlock *taint_block;
  llvm::Function *func;
  llvm::Module *module;
  llvm::LLVMContext *context;

//  llvm::AllocaInst *GetTaint(llvm::Value *val);

  // Mapping of instructions in a function to their taint locations.
  std::unordered_map<llvm::Value *, llvm::AllocaInst *> func_taints;

  std::unordered_map<std::string, uintptr_t> tainted_consts;
  std::unordered_map<std::string, uintptr_t> tainted_funcs;
};

}  // namespace vmill

#endif  // TOOLS_TAINT_TAINT_H_
