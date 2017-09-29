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

#include "remill/Arch/Arch.h"
#include "remill/BC/Compat/FileSystem.h"
#include "remill/BC/Compat/JITSymbol.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

#include "vmill/BC/Executor.h"
#include "vmill/BC/Runtime.h"

namespace vmill {
namespace {

static void InitializeCodeGenOnce(void) {
  static bool is_initialized = false;
  if (!is_initialized) {
    llvm::InitializeAllTargets();
    llvm::InitializeAllTargetMCs();
    llvm::InitializeAllAsmPrinters();
    llvm::InitializeAllAsmParsers();
    llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
    is_initialized = true;
  }
}

// Emulates `-mtune=native`. We want the compiled code to run as well as it
// can on the current machine.
static std::string GetNativeFeatureString(void) {
  llvm::SubtargetFeatures target_features;
  llvm::StringMap<bool> host_features;
  if (llvm::sys::getHostCPUFeatures(host_features)) {
    for (auto &feature : host_features) {
      target_features.AddFeature(feature.first(), feature.second);
    }
  }
  return target_features.getString();
}

// Figure out what file type should be be created by the JIT.
static llvm::file_magic::Impl ObjectFileType(void) {
  switch (remill::GetHostArch()->os_name) {
    case remill::kOSInvalid:
      return llvm::file_magic::unknown;

    case remill::kOSmacOS:
      return llvm::file_magic::macho_dynamically_linked_shared_lib;

    case remill::kOSLinux:
      return llvm::file_magic::elf_shared_object;

    // TODO(pag): Is this right?
    case remill::kOSWindows:
      return llvm::file_magic::coff_object;
  }
}

// Packages up all things related to dynamically generated shared libraries.
class CompiledObject {
 public:
  explicit CompiledObject(llvm::JITSymbolResolver &resolver)
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

  llvm::SectionMemoryManager mman;
  llvm::RuntimeDyld loader;
  std::unique_ptr<llvm::ObjectMemoryBuffer> buff;
  std::unique_ptr<llvm::object::ObjectFile> file;

 private:
  CompiledObject(void) = delete;
};

// MCJIT-based executor for bitcode.
class NativeExecutor : public Executor, llvm::JITSymbolResolver {
 public:
  explicit NativeExecutor(const std::shared_ptr<llvm::LLVMContext> &context_);

  virtual ~NativeExecutor(void);

  void Execute(void) override;

 protected:
  // Call into the runtime to allocate a `State` structure, and fill it with
  // the bytes from `data`.
  void *AllocateStateInRuntime(const std::string &data) override;

 private:
  friend class CompiledObject;

  NativeExecutor(void) = delete;

  llvm::JITSymbol findSymbolInLogicalDylib(
      const std::string &name) override;

  llvm::JITSymbol findSymbol(const std::string &Name) override;

  std::unique_ptr<CompiledObject> Compile(
      const std::unique_ptr<llvm::Module> &module);

  llvm::TargetOptions options;
  std::unique_ptr<llvm::TargetMachine> machine;

  std::vector<std::unique_ptr<CompiledObject>> libs;
  std::unique_ptr<CompiledObject> runtime_lib;

  // Cache of symbols used during dynamic symbol resolution.
  std::unordered_map<std::string, uintptr_t> syms;
};

// Compile the code in `module` into a
std::unique_ptr<CompiledObject> NativeExecutor::Compile(
    const std::unique_ptr<llvm::Module> &module) {

  llvm::MCContext *machine_context = nullptr;
  llvm::SmallVector<char, 4096> byte_buff;
  llvm::raw_svector_ostream byte_buff_stream(byte_buff);

  llvm::legacy::PassManager pm;
  auto cant_codegen = machine->addPassesToEmitMC(
      pm, machine_context, byte_buff_stream, true /* DisableVerify */);

  CHECK(!cant_codegen)
      << "Unable to add MCJIT code generation passes.";

  pm.run(*module.get());

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

  std::unique_ptr<CompiledObject> lib(new CompiledObject(*this));
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
    : Executor(context_) {

  LOG(INFO)
      << "Initializing native executor.";

  InitializeCodeGenOnce();

  auto cpu = llvm::sys::getHostCPUName();
  auto host_arch = remill::GetHostArch();
  auto runtime = vmill::LoadTargetRuntime(context);
  auto host_triple = host_arch->Triple().str();

  runtime->setTargetTriple(host_triple);
  runtime->setDataLayout(host_arch->DataLayout());

  std::string error;
  auto target = llvm::TargetRegistry::lookupTarget(host_triple, error);

  CHECK(target != nullptr)
      << "Unable to identify the target triple: " << error;

  machine = std::unique_ptr<llvm::TargetMachine>(target->createTargetMachine(
      host_triple, cpu, GetNativeFeatureString(), options,
      llvm::Reloc::PIC_, llvm::CodeModel::Default,
      llvm::CodeGenOpt::Aggressive));

  CHECK(machine)
      << "Cannot create target machine for triple "
      << host_triple << " and CPU " << cpu.str();

  LOG(INFO) << "Compiling target runtime";
  runtime_lib = Compile(runtime);
  runtime_lib->Finalize();
  LOG(INFO) << "Compiled target runtime.";
}

// Defer to the SectionMemoryManager on the top of the library stack to find
// local symbols.
llvm::JITSymbol NativeExecutor::findSymbolInLogicalDylib(
    const std::string &name) {
  if (runtime_lib) {
    return runtime_lib->mman.findSymbolInLogicalDylib(name);
  } else {
    return llvm::JITSymbol(nullptr);
  }
}

// Find compiled symbols.
llvm::JITSymbol NativeExecutor::findSymbol(const std::string &name) {
  auto &sym = syms[name];
  if (!sym && runtime_lib) {
    if (auto sym_ptr = runtime_lib->loader.getSymbolLocalAddress(name)) {
      sym = reinterpret_cast<uintptr_t>(sym_ptr);
    }

    if (!sym) {
      if (auto dsym = runtime_lib->mman.findSymbolInLogicalDylib(name)) {
        sym = dsym.getAddress() IF_LLVM_GTE_50(.get());
      }
    }

    if (!sym) {
      if (auto dsym = runtime_lib->mman.findSymbol(name)) {
        sym = dsym.getAddress() IF_LLVM_GTE_50(.get());
      }
    }
  }

  // The symbol isn't exposed in one of the compiled modules; try to find
  // it as a global symbol within the program itself.
  if (!sym) {
    sym = reinterpret_cast<uintptr_t>(dlsym(nullptr, name.c_str()));
  }

  if (!sym) {
    LOG(ERROR)
        << "Unable to find symbol " << name << "; it may not be compiled yet";
    return llvm::JITSymbol(nullptr);
  }

  return llvm::JITSymbol(sym, llvm::JITSymbolFlags::None);
}

NativeExecutor::~NativeExecutor(void) {}

// Call into the runtime to allocate a `State` structure, and fill it with
// the bytes from `data`.
void *NativeExecutor::AllocateStateInRuntime(const std::string &data) {
  auto alloc_sym = findSymbol("__vmill_allocate_state");
  CHECK(alloc_sym)
      << "Unable to find `__vmill_allocate_state` intrinsic.";
  auto alloc = reinterpret_cast<void *(*)(void)>(
      alloc_sym.getAddress() IF_LLVM_GTE_50(.get()));
  auto state = alloc();
  memcpy(state, data.data(), data.size());
  return state;
}

}  // namespace

Executor::Executor(const std::shared_ptr<llvm::LLVMContext> &context_)
    : context(context_) {}

Executor::~Executor(void) {}

Executor *Executor::GetNativeExecutor(
    const std::shared_ptr<llvm::LLVMContext> &context_) {
  return new NativeExecutor(context_);
}

void NativeExecutor::Execute(void) {
  auto resume = findSymbol("__vmill_resume");
  LOG(ERROR)
      << "__vmill_resume at " << std::hex
      << resume.getAddress() IF_LLVM_GTE_50(.get());
}

}  // namespace vmill
