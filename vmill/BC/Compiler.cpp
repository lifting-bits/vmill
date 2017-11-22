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

#include <memory>
#include <string>
#include <sys/mman.h>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/Triple.h>
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
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/Compat/FileSystem.h"
#include "remill/BC/Version.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/BC/Compiler.h"
#include "vmill/Util/Timer.h"

DEFINE_bool(disable_optimizer, false,
            "Should the optimized machine code be produced?");

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
      target_features.AddFeature(
          feature.first() _IF_LLVM_GTE_37(feature.second));
    }
  }
  return target_features.getString();
}

static llvm::CodeGenOpt::Level CodeGenOptLevel(void) {
  // TODO(pag): Using anything above `None` produces bugs :-(
  if (FLAGS_disable_optimizer) {
    return llvm::CodeGenOpt::None;
  } else {
    return llvm::CodeGenOpt::Aggressive;
  }
}

}  // namespace

Compiler::~Compiler(void) {}

Compiler::Compiler(const std::shared_ptr<llvm::LLVMContext> &context_)
    : context(context_),
      host_arch(remill::GetHostArch()) {

  InitializeCodeGenOnce();
  auto cpu = llvm::sys::getHostCPUName();
  auto host_triple = host_arch->Triple().str();

  std::string error;
  auto target = llvm::TargetRegistry::lookupTarget(host_triple, error);

  CHECK(target != nullptr)
      << "Unable to identify the target triple: " << error;

  machine = std::unique_ptr<llvm::TargetMachine>(target->createTargetMachine(
      host_triple, cpu, GetNativeFeatureString(), options,
      llvm::Reloc::PIC_, llvm::CodeModel::JITDefault,
      CodeGenOptLevel()));

  CHECK(machine)
      << "Cannot create target machine for triple "
      << host_triple << " and CPU " << cpu.str();
}

void Compiler::CompileModuleToFile(llvm::Module &module,
                                   const std::string &path) {
  Timer timer;
  module.setTargetTriple(host_arch->Triple().str());
  module.setDataLayout(host_arch->DataLayout().getStringRepresentation());

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 6)
  std::string error_message;
  llvm::raw_fd_ostream os(path.c_str(), error_message, llvm::sys::fs::F_None);
  CHECK(!os.has_error())
      << "Unable to open " << path << " for writing compiled module: "
      << error_message;
#else
  std::error_code error_code;
  llvm::raw_fd_ostream os(path, error_code, llvm::sys::fs::F_None);
  CHECK(!error_code)
      << "Unable to open " << path << " for writing compiled module: "
      << error_code.message();
#endif

  llvm::MCContext *machine_context = nullptr;

  llvm::legacy::PassManager pm;
  auto cant_codegen = machine->addPassesToEmitMC(
      pm, machine_context, os, true /* DisableVerify */);

  CHECK(!cant_codegen)
      << "Unable to add compilation passes.";

  pm.run(module);

  DLOG(INFO)
      << "Compiled and saved module to " << path << " in "
      << std::dec << timer.ElapsedSeconds() << " seconds";
}

}  // namespace vmill
