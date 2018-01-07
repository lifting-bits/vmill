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

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

#include <sstream>
#include <unordered_map>
#include <utility>

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/Program/ShadowMemory.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Workspace/Workspace.h"

#include "tools/Fuzzer/Fuzzer.h"

namespace vmill {
namespace {

using Location = uint32_t;

static void CoverSelect(Location loc, bool cond) {

}

static void CoverSwitch(Location edge, const Location *edges_begin,
                        const Location *edges_end) {

}

static void CoverBranch(Location edge, Location not_taken_edge) {

}

static void CoverPreTrace(Location from_loc) {

}

static void CoverTrace(Location to_loc) {

}

static int OpenLocationFile(void) {
  std::stringstream ss;
  ss << Workspace::ToolDir() << remill::PathSeparator() << "last_location";
  auto loc_file_name = ss.str();
  auto fd = open(loc_file_name.c_str(), O_RDWR | O_CREAT, 0666);
  auto err = errno;
  CHECK(-1 != fd)
      << "Could not open or create " << loc_file_name << ": "
      << strerror(err);

  return fd;
}

static Location GetCurrentLocation(int fd) {
  auto size = remill::FileSize(fd);

  if (size == sizeof(Location)) {
    Location loc = 0;
    CHECK(0 < read(fd, &loc, sizeof(loc)));
    return loc;

  } else if (size) {
    LOG(FATAL)
        << "Corrupted last-location file?";
  }
  return 0;
}

static void SetCurrentLocation(int fd, Location new_loc) {
  ftruncate(fd, 0);
  write(fd, &new_loc, sizeof(new_loc));
}

class CodeCoverageTool : public Tool {
 public:
  CodeCoverageTool(void)
      : loc_fd(OpenLocationFile()),
        loc(GetCurrentLocation(loc_fd)),
        module(nullptr),
        bool_type(nullptr),
        loc_type(nullptr),
        cov_select_func(nullptr),
        cov_branch_func(nullptr),
        cov_switch_func(nullptr),
        cov_pre_trace_func(nullptr),
        cov_trace_func(nullptr) {}

  virtual ~CodeCoverageTool(void) {
    SetCurrentLocation(loc_fd, loc);
    close(loc_fd);
  }

  void SetUp(void) override {

  }

  void TearDown(void) override {

  }

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol.
  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) override {

    if (name == "__cov_select") {
      return reinterpret_cast<uintptr_t>(CoverSelect);
    } else if (name == "__cov_switch") {
      return reinterpret_cast<uintptr_t>(CoverSwitch);
    } else if (name == "__cov_branch") {
      return reinterpret_cast<uintptr_t>(CoverBranch);
    } else if (name == "__cov_pre_trace") {
      return reinterpret_cast<uintptr_t>(CoverPreTrace);
    } else if (name == "__cov_trace") {
      return reinterpret_cast<uintptr_t>(CoverTrace);
    } else {
      return resolved;
    }
  }

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
    InitForModule(func->getParent());

    std::vector<llvm::BranchInst *> branches;
    std::vector<llvm::SelectInst *> selects;
    std::vector<llvm::SwitchInst *> switches;
    std::vector<llvm::CallInst *> calls;

    for (auto &block : *func) {
      for (auto &inst : block) {
        if (auto br = llvm::dyn_cast<llvm::BranchInst>(&inst)) {
          branches.push_back(br);
        } else if (auto sel = llvm::dyn_cast<llvm::SelectInst>(&inst)) {
          selects.push_back(sel);
        } else if (auto sw = llvm::dyn_cast<llvm::SwitchInst>(&inst)) {
          switches.push_back(sw);
        } else if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
          calls.push_back(call);
        }
      }
    }

    for (auto inst : branches) {
      Instrument(inst);
    }
    for (auto inst : selects) {
      Instrument(inst);
    }
    for (auto inst : switches) {
      Instrument(inst);
    }
    for (auto inst : calls) {
      Instrument(inst);
    }

    if (pc) {
      auto entry_block = &(func->getEntryBlock());
      llvm::IRBuilder<> ir(entry_block, entry_block->getFirstInsertionPt());
      ir.CreateCall(cov_trace_func, llvm::ConstantInt::get(loc_type, loc++));
    }
    func->dump();
    return true;
  }

 private:
  void InitForModule(llvm::Module *module_) {
    if (module == module_) {
      return;
    }

    module = module_;
    auto &context = module->getContext();
    auto void_type = llvm::Type::getVoidTy(context);
    bool_type = llvm::Type::getInt1Ty(context);
    loc_type = llvm::Type::getIntNTy(context, sizeof(Location) * 8);

    llvm::Type *select_arg_types[] = {loc_type, bool_type};
    cov_select_func = module->getOrInsertFunction(
        "__cov_select",
        llvm::FunctionType::get(void_type, select_arg_types, false));

    llvm::Type *branch_arg_types[] = {loc_type, loc_type};
    cov_branch_func = module->getOrInsertFunction(
        "__cov_branch",
        llvm::FunctionType::get(void_type, branch_arg_types, false));

    auto loc_ptr_type = llvm::PointerType::get(loc_type, 0);
    llvm::Type *switch_arg_types[] = {loc_type, loc_ptr_type, loc_ptr_type};
    cov_switch_func = module->getOrInsertFunction(
        "__cov_switch",
        llvm::FunctionType::get(void_type, switch_arg_types, false));

    cov_pre_trace_func = module->getOrInsertFunction(
        "__cov_pre_trace",
        llvm::FunctionType::get(void_type, loc_type, false));

    cov_trace_func = module->getOrInsertFunction(
        "__cov_trace",
        llvm::FunctionType::get(void_type, loc_type, false));
  }

  void Instrument(llvm::BranchInst *inst) {
    if (!inst->isConditional()) {
      return;
    }

    auto src_block = inst->getParent();
    auto taken_block = BlockForEdge(src_block, inst->getSuccessor(0));
    auto not_taken_block = BlockForEdge(src_block, inst->getSuccessor(1));

    inst->setSuccessor(0, taken_block);
    inst->setSuccessor(1, not_taken_block);

    llvm::IRBuilder<> ir(taken_block, taken_block->getFirstInsertionPt());
    llvm::Value *args[] = {
        llvm::ConstantInt::get(loc_type, loc++),
        llvm::ConstantInt::get(loc_type, loc++)};
    ir.CreateCall(cov_branch_func, args);

    ir.SetInsertPoint(not_taken_block, not_taken_block->getFirstInsertionPt());
    std::swap(args[0], args[1]);
    ir.CreateCall(cov_branch_func, args);
  }

  void Instrument(llvm::SwitchInst *inst) {
    return;
    auto src_block = inst->getParent();

    std::vector<Location> locs;
    std::vector<llvm::BasicBlock *> blocks;

    // Normal cases.
    for (auto &case_entry : inst->cases()) {
      auto edge_block = BlockForEdge(src_block, case_entry.getCaseSuccessor());
      blocks.push_back(edge_block);
      locs.push_back(loc++);
    }

    // Re-assign the successors.
    unsigned i = 0;
    for (auto block : blocks) {
      inst->setSuccessor(i, block);
    }

    // Default case.
    if (auto default_block = inst->getDefaultDest()) {
      default_block = BlockForEdge(src_block, default_block);
      blocks.push_back(default_block);
      locs.push_back(loc++);
      inst->setDefaultDest(default_block);
    }

    auto &context = inst->getContext();
    auto loc_array = llvm::ConstantDataArray::get(context, locs);
    auto loc_var = new llvm::GlobalVariable(
        *module, loc_array->getType(), true,
        llvm::GlobalValue::PrivateLinkage, loc_array);

    auto first_entry = llvm::ConstantExpr::getGetElementPtr(
        loc_type, loc_var, llvm::ConstantInt::get(loc_type, 0));
    auto after_last_entry = llvm::ConstantExpr::getGetElementPtr(
        loc_type, loc_var, llvm::ConstantInt::get(loc_type, 1));

    llvm::Value *args[] = {
        nullptr,
        first_entry,
        after_last_entry};

    i = 0;
    for (auto block : blocks) {
      args[0] = llvm::ConstantInt::get(loc_type, locs[i++]);
      llvm::IRBuilder<> ir(block, block->getFirstInsertionPt());
      ir.CreateCall(cov_switch_func, args);
    }
  }

  void Instrument(llvm::SelectInst *inst) {
    llvm::Value *args[] = {llvm::ConstantInt::get(loc_type, loc++),
                           inst->getCondition()};
    llvm::IRBuilder<> ir(inst);
    ir.CreateCall(cov_select_func, args);
  }

  void Instrument(llvm::CallInst *inst) {
    auto func = inst->getCalledFunction();
    if (!func) {
      return;
    }

    auto name = func->getName();
    if (name == "__remill_function_call" ||
        name == "__remill_function_return" ||
        name == "__remill_jump") {
      llvm::IRBuilder<> ir(inst);
      ir.CreateCall(cov_pre_trace_func,
                    llvm::ConstantInt::get(loc_type, loc++));
    }
  }

  llvm::BasicBlock *BlockForEdge(llvm::BasicBlock *,
                                 llvm::BasicBlock *to) {
    auto &context = to->getContext();
    auto mid = llvm::BasicBlock::Create(context, "", to->getParent(), to);

    llvm::IRBuilder<> ir(mid);
    ir.CreateBr(to);

    return mid;
  }

  int loc_fd;
  Location loc;

  llvm::Module *module;
  llvm::IntegerType *bool_type;
  llvm::IntegerType *loc_type;
  llvm::Constant *cov_select_func;
  llvm::Constant *cov_branch_func;
  llvm::Constant *cov_switch_func;
  llvm::Constant *cov_pre_trace_func;
  llvm::Constant *cov_trace_func;
};

}  // namespace

std::unique_ptr<Tool> CreateCodeCoverageTracker(void) {
  return std::unique_ptr<Tool>(new CodeCoverageTool);
}

}  // namespace vmill
