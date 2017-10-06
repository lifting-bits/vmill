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

#include "remill/Arch/Arch.h"
#include "remill/BC/Compat/FileSystem.h"
#include "remill/BC/Compat/JITSymbol.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

#include "vmill/BC/Executor.h"
#include "vmill/BC/Lifter.h"
#include "vmill/BC/Runtime.h"
#include "vmill/Context/AddressSpace.h"
#include "vmill/Context/Context.h"
#include "vmill/Util/Timer.h"

namespace vmill {
namespace {

inline static AddressSpace *AddressSpaceOf(void *memory) {
  return Context::gCurrent->AddressSpaceOf(memory);
}

extern "C" bool __vmill_can_read_byte(void *memory, uint64_t addr) {
  return AddressSpaceOf(memory)->CanRead(addr);
}

extern "C" bool __vmill_can_write_byte(void *memory, uint64_t addr) {
  return AddressSpaceOf(memory)->CanWrite(addr);
}

extern "C" void *__vmill_allocate_memory(void *memory, uint64_t where,
                                         uint64_t size) {
  auto addr_space = AddressSpaceOf(memory);
  addr_space->AddMap(where, size);
  return memory;
}

extern "C" void *__vmill_free_memory(void *memory, uint64_t where,
                                     uint64_t size) {
  auto addr_space = AddressSpaceOf(memory);
  addr_space->RemoveMap(where, size);
  return memory;
}

extern "C" void *__vmill_protect_memory(void *memory, uint64_t where,
                                        uint64_t size, bool can_read,
                                        bool can_write, bool can_exec) {
  auto addr_space = AddressSpaceOf(memory);
  addr_space->SetPermissions(where, size, can_read, can_write, can_exec);
  return memory;
}

extern "C" uint64_t __vmill_next_memory_end(void *memory, uint64_t where) {
  auto addr_space = AddressSpaceOf(memory);
  uint64_t nearest_end = 0;
  if (addr_space->NearestLimitAddress(where, &nearest_end)) {
    return nearest_end;
  } else {
    return 0;
  }
}

extern "C" uint64_t __vmill_prev_memory_begin(void *memory, uint64_t where) {
  auto addr_space = AddressSpaceOf(memory);
  uint64_t nearest_begin = 0;
  if (addr_space->NearestBaseAddress(where, &nearest_begin)) {
    return nearest_begin;
  } else {
    return 0;
  }
}

extern "C" void *__vmill_schedule(void *state, uint64_t pc, void *memory,
                                  TaskStatus status) {
  Task task = {state, pc, memory, status};
  Context::gCurrent->ScheduleTask(task);
  return nullptr;
}

template <typename RT, typename ST, size_t source_size>
inline static RT ReadMemory(void *memory, uint64_t addr) {
  static_assert(sizeof(ST) >= source_size,
                "Invalid `source_size` to `ReadMemory`.");

  auto addr_space = AddressSpaceOf(memory);
  alignas(ST) uint8_t data[sizeof(ST)] = {};
  _Pragma("unroll")
  for (uint64_t i = 0; i < source_size; ++i) {
    if (!addr_space->TryRead(addr + i, &(data[i]))) {
      LOG(ERROR)
          << "Invalid memory read access to address "
          << std::hex << (addr + i) << " when trying to read "
          << std::dec << source_size << "-byte object starting from address "
          << std::hex << addr << std::dec;
      memset(data, 0, sizeof(ST));
      break;
    }
  }
  return static_cast<RT>(reinterpret_cast<ST &>(data[0]));
}

#define MAKE_MEM_READ(ret_type, read_type, suffix, read_size) \
    extern "C" ret_type __remill_read_memory_ ## suffix( \
        void *memory, uint64_t addr) { \
      return ReadMemory<ret_type, read_type, read_size>(memory, addr); \
    }

MAKE_MEM_READ(uint8_t, uint8_t, 8, 1)
MAKE_MEM_READ(uint16_t, uint16_t, 16, 2)
MAKE_MEM_READ(uint32_t, uint32_t, 32, 4)
MAKE_MEM_READ(uint64_t, uint64_t, 64, 8)
MAKE_MEM_READ(float, float, f32, 4)
MAKE_MEM_READ(double, double, f64, 8)
MAKE_MEM_READ(double, long double, f80, 10)

#undef MAKE_MEM_READ

template <typename ST, typename DT, size_t dest_size>
inline static void WriteMemory(void *memory, uint64_t addr, ST val_) {
  static_assert(sizeof(DT) >= dest_size,
                "Invalid `dest_size` to `WriteMemory`.");

  auto addr_space = AddressSpaceOf(memory);
  auto val = static_cast<DT>(val_);
  alignas(DT) uint8_t data[sizeof(DT)] = {};
  memcpy(data, &val, dest_size);

  _Pragma("unroll")
  for (uint64_t i = 0; i < dest_size; ++i) {
    if (!addr_space->TryWrite(addr + i, data[i])) {
      LOG(ERROR)
          << "Invalid memory write access to address "
          << std::hex << (addr + i) << " when trying to write "
          << std::dec << dest_size << "-byte object starting from address "
          << std::hex << addr << std::dec;
    }
  }
}

#define MAKE_MEM_WRITE(input_type, write_type, suffix, write_size) \
    extern "C" void *__remill_write_memory_ ## suffix( \
        void *memory, uint64_t addr, input_type val) { \
      WriteMemory<input_type, write_type, write_size>(memory, addr, val); \
      return memory; \
    }

MAKE_MEM_WRITE(uint8_t, uint8_t, 8, 1)
MAKE_MEM_WRITE(uint16_t, uint16_t, 16, 2)
MAKE_MEM_WRITE(uint32_t, uint32_t, 32, 4)
MAKE_MEM_WRITE(uint64_t, uint64_t, 64, 8)
MAKE_MEM_WRITE(float, float, f32, 4)
MAKE_MEM_WRITE(double, double, f64, 8)
MAKE_MEM_WRITE(double, long double, f80, 10)

#undef MAKE_MEM_WRITE

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

  llvm::TargetOptions options;
  std::unique_ptr<llvm::TargetMachine> machine;

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
  runtime_lib = Compile(runtime.get());
  runtime_lib->Finalize();
  LOG(INFO) << "Compiled target runtime.";

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
    LOG(INFO)
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

  compiled_func(task.state, task.pc, task.memory);

//  resume(task.state, task.pc, task.memory, task.status, compiled_func);
}

}  // namespace vmill
