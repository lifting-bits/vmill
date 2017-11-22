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

#include <ctime>
#include <dlfcn.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/Triple.h>
#include <llvm/ExecutionEngine/ObjectMemoryBuffer.h>
#include <llvm/ExecutionEngine/RuntimeDyld.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/MC/MCContext.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include "../../../../remill/BC/Compat/RuntimeDyld.h"
#include "../Program/Context.h"
#include "remill/Arch/Arch.h"
#include "remill/BC/Compat/FileSystem.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

#include "vmill/BC/Executor.h"
#include "vmill/BC/Lifter.h"
#include "vmill/BC/Runtime.h"
#include "vmill/Memory/AddressSpace.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Util/Timer.h"


namespace vmill {
namespace {




// Packages up all things related to dynamically generated shared libraries.
class CompiledModule {
 public:
  explicit CompiledModule(llvm::JITSymbolResolver &resolver)
      : loader(mman, resolver) {

    // Don't allocate memory for sections that aren't needed for execution.
    loader.setProcessAllSections(false);
  }

  void Finalize(void) {
    loader.resolveRelocations();
    std::string error;
    CHECK(!mman.finalizeMemory(&error))
        << "Unable to finalize JITed code memory: " << error;
  }

  uintptr_t AddressOfSymbol(const std::string &name) {
    if (auto eval_sym = loader.getSymbol(name)) {
      return eval_sym.getAddress();
    }

    auto dsym = mman.findSymbolInLogicalDylib(name);
    if (dsym) {
      return dsym.getAddress() IF_LLVM_GTE_50(.get());
    }

    dsym = mman.findSymbol(name);
    if (dsym) {
      return dsym.getAddress() IF_LLVM_GTE_50(.get());
    }

    return 0;
  }

  llvm::SectionMemoryManager mman;
  llvm::RuntimeDyld loader;
  std::unique_ptr<llvm::ObjectMemoryBuffer> buff;
  std::unique_ptr<llvm::object::ObjectFile> file;

 private:
  CompiledModule(void) = delete;
};

// MCJIT-based executor for bitcode.
class NativeExecutor : public Executor, llvm::JITSymbolResolver {
 public:
  explicit NativeExecutor(const std::shared_ptr<llvm::LLVMContext> &context_);

  virtual ~NativeExecutor(void);

  void Execute(const Task &task, llvm::Function *func) override;

  // Call into the runtime to allocate a `State` structure, and fill it with
  // the bytes from `data`.
  void *AllocateStateInRuntime(const std::string &data) override;

 private:
  friend class CompiledModule;

  NativeExecutor(void) = delete;

  llvm::JITSymbol findSymbolInLogicalDylib(
      const std::string &name) override;

  llvm::JITSymbol findSymbol(const std::string &Name) override;

  CompiledModule *Compile(llvm::Module *module);



  CompiledModule *runtime_lib;

  using LiftedFunctionType = void(void *, uint64_t, void *);

  // Cache of symbols used during dynamic symbol resolution.
  std::unordered_map<std::string, uintptr_t> syms;

  // Cache mapping program counters to compiled functions.
  std::unordered_map<llvm::Module *, CompiledModule *> compiled_libs;
  std::unordered_map<llvm::Function *, LiftedFunctionType *> compiled_funcs;

  void *(*allocate_state)(void);
  void (*free_state)(void *);
  void (*resume)(void *, uint64_t, void *, TaskStatus, LiftedFunctionType *);

  LiftedFunctionType *CompileLiftedFunction(llvm::Function *func);

  template <typename T>
  T TryFindFunction(const char *name) {
    auto sym = findSymbol(name);
    if (sym) {
      return reinterpret_cast<T>(sym.getAddress() IF_LLVM_GTE_50(.get()));
    } else {
      return nullptr;
    }
  }

  template <typename T>
  T FindFunction(const char *name) {
    auto sym = TryFindFunction<T>(name);
    CHECK(sym != nullptr)
       << "Unable to find " << name << " in compiled code.";
    return sym;
  }
};


// Compile the code in `module` into a compiled object.
CompiledModule *NativeExecutor::Compile(llvm::Module *module) {
  llvm::MCContext *machine_context = nullptr;
  llvm::SmallVector<char, 4096> byte_buff;
  llvm::raw_svector_ostream byte_buff_stream(byte_buff);

  llvm::legacy::PassManager pm;
  auto cant_codegen = machine->addPassesToEmitMC(
      pm, machine_context, byte_buff_stream, true /* DisableVerify */);

  CHECK(!cant_codegen)
      << "Unable to add MCJIT code generation passes.";

  pm.run(*module);

  std::unique_ptr<llvm::ObjectMemoryBuffer> obj_buff(
      new llvm::ObjectMemoryBuffer(std::move(byte_buff)));

  auto obj_file_exp = llvm::object::ObjectFile::createObjectFile(
      *obj_buff, ObjectFileType());

  std::string error;
  if (!obj_file_exp) {
#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 9)
    LOG(FATAL)
            << "Failed to load JIT-compiled object file from memory";
#else
    LOG(FATAL)
        << "Failed to load JIT-compiled object file from memory: "
        << llvm::toString(obj_file_exp.takeError());
#endif
  }


  auto lib = new CompiledModule(*this);
  lib->file = std::move(*obj_file_exp);
  lib->buff = std::move(obj_buff);

  auto info = lib->loader.loadObject(*lib->file.get());
  CHECK(!lib->loader.hasError())
      << "Unable to load JIT-compiled object into a dyld: "
      << lib->loader.getErrorString().str();

  return lib;
}

// Initialize the native code executor.
NativeExecutor::NativeExecutor(
    const std::shared_ptr<llvm::LLVMContext> &context_)
    : Executor(context_),
      runtime_lib(nullptr),
      allocate_state(nullptr),
      free_state(nullptr) {

  LOG(INFO)
      << "Initializing native executor.";



  auto runtime = vmill::LoadTargetRuntime(context);


  runtime->setTargetTriple(host_triple);
  runtime->setDataLayout(host_arch->DataLayout());





  LOG(INFO) << "Compiling target runtime";
  runtime_lib = Compile(runtime.get());
  runtime_lib->Finalize();
  LOG(INFO) << "Compiled target runtime.";

  // TODO(pag): Call global constructors in loaded library???

  resume = FindFunction<decltype(resume)>("__vmill_resume");
  allocate_state = FindFunction<decltype(allocate_state)>(
      "__vmill_allocate_state");
  free_state = FindFunction<decltype(free_state)>("__vmill_free_state");
}

// Defer to the SectionMemoryManager on the top of the library stack to find
// local symbols.
llvm::JITSymbol NativeExecutor::findSymbolInLogicalDylib(
    const std::string &name) {
  uint64_t addr = 0;

//  if (libs.size()) {
//    addr = libs.back()->AddressOfSymbol(name);
//  }

  if (!addr && runtime_lib) {
    addr = runtime_lib->AddressOfSymbol(name);
  }

  return llvm::JITSymbol(addr, llvm::JITSymbolFlags::None);
}

// Find compiled symbols.
llvm::JITSymbol NativeExecutor::findSymbol(const std::string &name) {
  return findSymbolInLogicalDylib(name);
}

NativeExecutor::~NativeExecutor(void) {
  for (auto &entry : compiled_libs) {
    delete entry.second;
  }
  delete runtime_lib;
}

// Call into the runtime to allocate a `State` structure, and fill it with
// the bytes from `data`.
void *NativeExecutor::AllocateStateInRuntime(const std::string &data) {
  LOG(INFO)
      << "Allocating " << std::dec << data.size()
      << " bytes for machine state";

  auto state = allocate_state();
  memcpy(state, data.data(), data.size());
  return state;
}

}  // namespace

Executor *Executor::GetNativeExecutor(
    const std::shared_ptr<llvm::LLVMContext> &context_) {
  return new NativeExecutor(context_);
}

// Compile a lifted function into machine code.
[[gnu::noinline]]
NativeExecutor::LiftedFunctionType *NativeExecutor::CompileLiftedFunction(
    llvm::Function *func) {

  // Prepare the module for compiling on the current architecture.
  auto host_arch = remill::GetHostArch();
  auto module = func->getParent();
  auto &compiled_module = compiled_libs[module];
  if (!compiled_module) {
    Timer timer;
    module->setTargetTriple(host_arch->Triple().str());
    module->setDataLayout(host_arch->DataLayout());
    compiled_module = Compile(module);
    compiled_module->Finalize();
    DLOG(INFO)
        << "JIT compiled module in " << std::dec << timer.ElapsedSeconds()
        << " seconds";
  }

  // Find the lifted function.
  const auto func_name = func->getName().str();
  auto code = reinterpret_cast<LiftedFunctionType *>(
      compiled_module->AddressOfSymbol(func_name));

  if (!code) {
    LOG(FATAL)
        << "Unable to locate or compile function " << func_name
        << " in emulated address space";
  }

  return code;
}

void NativeExecutor::Execute(const Task &task, llvm::Function *func) {

  auto &compiled_func = compiled_funcs[func];
  if (!compiled_func) {
    compiled_func = CompileLiftedFunction(func);
  }

  resume(task.state, task.pc, task.memory, task.status, compiled_func);
}

}  // namespace vmill
