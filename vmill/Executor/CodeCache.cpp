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

#include <cerrno>
#include <map>
#include <vector>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <unordered_map>

#include <llvm/ExecutionEngine/JITEventListener.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBuffer.h>

#include "remill/BC/Compat/Error.h"
#include "remill/BC/Compat/RuntimeDyld.h"
#include "remill/BC/Compat/JITSymbol.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

#include "vmill/BC/Compiler.h"
#include "vmill/BC/Optimize.h"
#include "vmill/Executor/CodeCache.h"
#include "vmill/Program/AddressSpace.h"
#include "vmill/Util/AreaAllocator.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Workspace/Tool.h"
#include "vmill/Workspace/Workspace.h"

#include <gflags/gflags.h>

extern "C" {
// Used to register exception handling frames with the JIT.
__attribute__((weak))
extern void __register_frame(void *);

}  // extern C
namespace vmill {
namespace {

// An entry in the `.translated` section of a JIT-compiled module.
struct CacheIndexEntry {
  TraceId trace_id;
  Memory *(*lifted_function)(ArchState *, PC, Memory *);
} __attribute__((packed));

// Memory mapped for JITed code or data.
struct MemoryMap {
  uint8_t *base;
  uintptr_t size;
  unsigned section_id;
  bool can_read;
  bool can_write;
  bool can_exec;
  bool is_index;
  bool is_ctors;
  std::string source_file;

  inline bool operator<(const MemoryMap &that) const {
    return base < that.base;
  }
};

class CodeCacheImpl : public CodeCache,
                      public llvm::RuntimeDyld::MemoryManager,
                      public llvm::JITSymbolResolver {
 public:
  CodeCacheImpl(std::unique_ptr<Tool> tool_,
                const std::shared_ptr<llvm::LLVMContext> &context_);

  virtual ~CodeCacheImpl(void);

  LiftedFunction *Lookup(TraceId trace_id) const final;

  uintptr_t Lookup(const char *symbol) final;

  // Called to run constructors in the runtime.
  void RunConstructors(void) final {
    if (constructors.empty()) {
      return;
    }

    for (auto ctor : constructors) {
      ctor();
    }
    LOG(INFO)
        << "Ran " << constructors.size() << " constructors";
    constructors.clear();
  }

  // Called just before the beginning of a run.
  void SetUp(void) final {
    tool->SetUp();
  }

  // Called just after the end of a run.
  void TearDown(void) final {
    tool->TearDown();
  }

  // Load the runtime library, this must be done first, as it supported all
  // lifted code execution.
  void LoadRuntimeLibrary(void);

  // Load a JIT-compiled module from a file `path`.
  void LoadLibrary(const std::string &path, bool is_runtime=false);

  // Load all JIT-compiled modules from the libraries directory. Returns the
  // number of loaded libraries.
  int LoadLibraries(void);

  // JIT compile any already lifted bitcode.
  void ReloadLibraries(void);

  // Implementing the `CodeCache` interface. This takes ownership of the
  // module.
  void AddModuleToCache(const std::unique_ptr<llvm::Module> &module) final;

  // Implementing the `llvm::RuntimeDyld::MemoryManager` interface:

  // Allocate memory for a code section.
  uint8_t *allocateCodeSection(uintptr_t size, unsigned alignment,
                               unsigned section_id, llvm::StringRef) final;

  /// Allocate memory for a data section.
  uint8_t *allocateDataSection(uintptr_t size, unsigned alignment,
                               unsigned section_id, llvm::StringRef,
                               bool is_read_only) final;

  // Register exception handling frames.
  void registerEHFrames(uint8_t *addr, uint64_t load_addr,
                        size_t size) final;

  // We never unload JITed code.
  void deregisterEHFrames(
      IF_LLVM_LT(5, 0, uint8_t *, uint64_t, size_t)) final {}

  // Apply all final permissions to any pending JITed page ranges, moving
  // them into the `jit_ranges` list.
  bool finalizeMemory(std::string *error_message=nullptr) final;
  // Implementing the `llvm::JITSymbolResolver` interface.

  // Resolve symbols, including hidden symbols, for handling relocations.
  llvm::JITSymbol findSymbolInLogicalDylib(const std::string &name) IF_LLVM_LT_900(final);

  /// Resolve external/exported symbols during linking.
  llvm::JITSymbol findSymbol(const std::string &name) IF_LLVM_LT_900(final);

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(9, 0)
  // Returns the fully resolved address and flags for each of the given
  // symbols.
  //
  // This method will return an error if any of the given symbols can not be
  // resolved, or if the resolution process itself triggers an error.
  void lookup(const llvm::JITSymbolResolver::LookupSet &symbols,
              llvm::JITSymbolResolver::OnResolvedFunction on_resolved_cb) final;

  // Returns the subset of the given symbols that should be materialized by
  // the caller. Only weak/common symbols should be looked up, as strong
  // definitions are implicitly always part of the caller's responsibility.
  llvm::Expected<llvm::JITSymbolResolver::LookupSet>
  getResponsibilitySet(const llvm::JITSymbolResolver::LookupSet &symbols) final;

#endif

 private:
  CodeCacheImpl(void) = delete;

  bool LoadIndex(const MemoryMap &range, std::string *error_message);
  void LoadConstructors(const MemoryMap &range);

  void ReoptimizeModule(const std::unique_ptr<llvm::Module> &module);
  void InstrumentTraces(const std::unique_ptr<llvm::Module> &module);

  const std::unique_ptr<Tool> tool;

  const std::shared_ptr<llvm::LLVMContext> &context;

  Compiler compiler;
  AreaAllocator code_allocator;
  AreaAllocator data_allocator;
  AreaAllocator index_allocator;
  AreaAllocator ctor_allocator;

  llvm::JITEventListener *event_listener;
  std::map<uint8_t *, MemoryMap> jit_ranges;
  std::unordered_map<unsigned, MemoryMap> pending_jit_ranges;
  std::unique_ptr<llvm::RuntimeDyld> pending_loader;
  std::unique_ptr<llvm::RuntimeDyld> runtime_loader;
  std::string pending_source_file;
  std::unordered_map<TraceId, LiftedFunction *> lifted_functions;
  std::vector<void(*)(void)> constructors;
};

CodeCacheImpl::CodeCacheImpl(std::unique_ptr<Tool> tool_,
                             const std::shared_ptr<llvm::LLVMContext> &context_)
    : CodeCache(),
      tool(std::move(tool_)),
      context(context_),
      compiler(context_),
      code_allocator(kAreaRWX, kAreaCodeCacheCode),
      data_allocator(kAreaRW, kAreaCodeCacheData),
      index_allocator(kAreaRW, kAreaCodeCacheIndex),
      ctor_allocator(kAreaRW),
      event_listener(llvm::JITEventListener::createGDBRegistrationListener()) {
  LoadRuntimeLibrary();
  if (!LoadLibraries()) {
    ReloadLibraries();
  }
}

CodeCacheImpl::~CodeCacheImpl(void) {}

// Allocate memory for a code section.
uint8_t *CodeCacheImpl::allocateCodeSection(
    uintptr_t size, unsigned alignment, unsigned section_id,
    llvm::StringRef name) {
  MemoryMap map = {code_allocator.Allocate(size, alignment), size,
                   section_id, true, false, true, false, false,
                   pending_source_file};
  pending_jit_ranges[section_id] = map;
  return map.base;
}

// Allocate memory for a code section.
uint8_t *CodeCacheImpl::allocateDataSection(
    uintptr_t size, unsigned alignment, unsigned section_id,
    llvm::StringRef name, bool is_read_only) {
  uint8_t *base = nullptr;
  bool is_index = false;
  bool is_ctors = false;

  // If we're allocating translations then we want all entries across all
  // translation segments to be contiguous.
  if (name == ".vindex") {
    base = index_allocator.Allocate(size, 0);
    is_index = true;

  } else if (name == ".vctors") {
    base = ctor_allocator.Allocate(size, 0);
    is_ctors = true;

  } else {
    base = data_allocator.Allocate(size, alignment);
  }
  MemoryMap map = {base, size, section_id, true, !is_read_only,
                   false, is_index, is_ctors, pending_source_file};
  pending_jit_ranges[section_id] = map;
  return map.base;
}

// Register exception handling frames.
void CodeCacheImpl::registerEHFrames(uint8_t *addr, uint64_t, size_t) {
  if (__register_frame) {
    __register_frame(addr);
  }
}

bool CodeCacheImpl::LoadIndex(const MemoryMap &range,
                              std::string *error_message) {
  auto all_good = true;
  auto base = reinterpret_cast<CacheIndexEntry *>(range.base);
  auto limit = &(base[range.size / sizeof(CacheIndexEntry)]);

  for (; base < limit; ++base) {
    if (!static_cast<uint64_t>(base->trace_id.pc)) {
      continue;

    } else if (!code_allocator.Contains(base->lifted_function)) {
      if (error_message) {
        *error_message = "Lifted function address is not managed by the "
                         "code cache allocator.";
      } else {
        LOG(ERROR)
            << "Cache entry with trace id (" << std::hex
            << static_cast<uint64_t>(base->trace_id.pc) << ", "
            << static_cast<TraceHashBaseType>(base->trace_id.hash)
            << std::dec << ") and lifted code at "
            << reinterpret_cast<void *>(base->lifted_function)
            << " is not valid; the lifted code isn't inside the code cache!";
      }
      all_good = false;
      continue;
    }

    auto &lifted_func = lifted_functions[base->trace_id];
    if (lifted_func != nullptr) {
      LOG(ERROR)
          << "Code at " << reinterpret_cast<void *>(base->lifted_function)
          << " implementing trace with hash (" << std::hex
          << static_cast<uint64_t>(base->trace_id.pc) << ", "
          << static_cast<TraceHashBaseType>(base->trace_id.hash) << std::dec
          << ") already implemented at "
          << reinterpret_cast<void *>(lifted_func);
    } else {
      lifted_func = base->lifted_function;
    }
  }
  return all_good;
}

struct Constructor {
  uint32_t priority;
  void (*func)(void);
  void *data;
};

void CodeCacheImpl::LoadConstructors(const MemoryMap &range) {
  auto base = reinterpret_cast<Constructor *>(range.base);
  auto limit = &(base[range.size / sizeof(Constructor)]);

  for (; base < limit; ++base) {
    if (base->func) {
      constructors.push_back(base->func);
    }
  }
}

// Normally this function is meant to finalize permissions of any pending JITed
// page ranges. We this as the place to
bool CodeCacheImpl::finalizeMemory(std::string *error_message) {
  bool all_good = true;
  for (const auto &entry : pending_jit_ranges) {
    const auto &range = entry.second;
    jit_ranges[range.base] = range;

    if (range.is_ctors) {
      LoadConstructors(range);
    } else if (range.is_index) {
      all_good = LoadIndex(range, error_message) || all_good;
    }
  }
  pending_jit_ranges.clear();
  return all_good;
}

// Resolve symbols, including hidden symbols, for handling relocations.
llvm::JITSymbol CodeCacheImpl::findSymbolInLogicalDylib(
    const std::string &name) {
  uint64_t addr = 0;
  if (pending_loader) {
    addr = pending_loader->getSymbol(name).getAddress();
  }
  if (!addr && runtime_loader) {
    addr = runtime_loader->getSymbol(name).getAddress();
  }
  return llvm::JITSymbol(addr, llvm::JITSymbolFlags::None);
}

// Resolve external/exported symbols during linking.
llvm::JITSymbol CodeCacheImpl::findSymbol(const std::string &name) {
  auto addr = llvm::RTDyldMemoryManager::getSymbolAddressInProcess(name);
  auto resolved_addr = tool->FindSymbolForLinking(name, addr);
  if (!resolved_addr) {
    if (addr) {
      resolved_addr = addr;
    } else {
#ifdef __APPLE__
      auto uname = '_' + name;
      addr = llvm::RTDyldMemoryManager::getSymbolAddressInProcess(uname);
      resolved_addr = tool->FindSymbolForLinking(uname, addr);
      if (!resolved_addr) {
        if (addr) {
          resolved_addr = addr;
        } else {
          LOG(ERROR)
              << "Could not locate address of symbol " << name;
        }
      }
#else
      LOG(ERROR)
          << "Could not locate address of symbol " << name;
#endif
    }
  }
  return llvm::JITSymbol(resolved_addr, llvm::JITSymbolFlags::None);
}

// Load the runtime library, this must be done first, as it supported all
// lifted code execution.
void CodeCacheImpl::LoadRuntimeLibrary(void) {
  pending_source_file = Workspace::RuntimeLibraryPath();

  if (!remill::FileExists(pending_source_file)) {
    auto bitcode_path = Workspace::RuntimeBitcodePath();
    DLOG(INFO)
        << "Loading runtime library bitcode from " << bitcode_path;

    std::unique_ptr<llvm::Module> runtime(remill::LoadModuleFromFile(
        context.get(), bitcode_path));

    DLOG(INFO)
        << "Instrumenting runtime library";

    tool->PrepareModule(runtime.get());

    if (tool->InstrumentRuntime(runtime.get())) {
      DLOG(INFO)
          << "Optimizing instrumented runtime";
      ReoptimizeModule(runtime);
    }

    DLOG(INFO)
        << "JIT-compiling runtime library bitcode";
    compiler.CompileModuleToFile(*runtime, pending_source_file);
  }

  DLOG(INFO)
      << "Loading runtime library object code " << pending_source_file;
  LoadLibrary(pending_source_file, true);

  runtime_loader.swap(pending_loader);
}

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(9, 0)
// Returns the fully resolved address and flags for each of the given
// symbols.
//
// This method will return an error if any of the given symbols can not be
// resolved, or if the resolution process itself triggers an error.
void CodeCacheImpl::lookup(
    const llvm::JITSymbolResolver::LookupSet &symbols,
    llvm::JITSymbolResolver::OnResolvedFunction on_resolved_cb) {
  llvm::JITSymbolResolver::LookupResult result;
  for (auto sym_name : symbols) {
    if (llvm::JITSymbol found_sym = findSymbol(sym_name); found_sym) {
      if (auto addr = found_sym.getAddress(); addr) {
        llvm::JITEvaluatedSymbol sym_loc(*addr, found_sym.getFlags());
        result.emplace(sym_name, std::move(sym_loc));
      }
    }
  }
  on_resolved_cb(result);
}

// Returns the subset of the given symbols that should be materialized by
// the caller. Only weak/common symbols should be looked up, as strong
// definitions are implicitly always part of the caller's responsibility.
llvm::Expected<llvm::JITSymbolResolver::LookupSet>
CodeCacheImpl::getResponsibilitySet(
    const llvm::JITSymbolResolver::LookupSet &) {
  llvm::JITSymbolResolver::LookupSet result;
  return result;
//  for (auto sym_name : symbols) {
//    llvm::JITSymbol found_sym = findSymbol(sym_name);
//    if (found_sym && !found_sym.getFlags().isStrong()) {
//      result.insert(sym_name);
//    } else {
//      auto err = found_sym.takeError();
//      return std::move(err);
//    }
//  }
//  return result;
}

#endif

// Load a JIT-compiled module from a file `path`.
void CodeCacheImpl::LoadLibrary(const std::string &path, bool is_runtime) {
  pending_source_file = path;
  pending_loader.reset(new llvm::RuntimeDyld(*this, *this));

  auto maybe_buff_ptr = llvm::MemoryBuffer::getFile(
      pending_source_file, -1 /* FileSize */,
      false /* RequiresNullTerminator */);

  if (remill::IsError(maybe_buff_ptr)) {
    LOG(FATAL)
        << "Unable to open shared library " << pending_source_file << ": "
        << remill::GetErrorString(maybe_buff_ptr);
  }

  auto &buff_ptr = remill::GetReference(maybe_buff_ptr);
  auto maybe_obj_file_ptr = llvm::object::ObjectFile::createObjectFile(
      *buff_ptr);

  if (remill::IsError(maybe_obj_file_ptr)) {
    LOG(FATAL)
        << "Unable to load " << pending_source_file << " as an object file: "
        << remill::GetErrorString(maybe_obj_file_ptr);
  }

  auto &object_file_ptr = remill::GetReference(maybe_obj_file_ptr);
  auto info = pending_loader->loadObject(*object_file_ptr);
  if (!info) {
    if (pending_loader->hasError()) {
      LOG(FATAL)
          << "Unable to load " << pending_source_file << " as an object file: "
          << pending_loader->getErrorString().str();
    }
  } else {

    // Notify a debugger that the runtime has been loaded, so that the debugger
    // can go and find the symbols and such. We don't want to do this for lifted
    // code because that doesn't have much useful symbol information.
    if (is_runtime && event_listener) {
      IF_LLVM_LT_900(event_listener->NotifyObjectEmitted(*object_file_ptr, *info);)
      IF_LLVM_GTE_900(event_listener->notifyObjectLoaded(
          static_cast<uint64_t>(reinterpret_cast<uintptr_t>(
              object_file_ptr->getData().data())),
          *object_file_ptr, *info);)
    }
  }

  pending_loader->finalizeWithMemoryManagerLocking();

  // TODO(pag): Issue #12: Is the library's `_start` function called?
}

// Load all JIT-compiled modules from the libraries directory.
int CodeCacheImpl::LoadLibraries(void) {
  int num_loaded = 0;
  remill::ForEachFileInDirectory(Workspace::LibraryDir(),
      [&num_loaded, this] (const std::string &path) {
        DLOG(INFO)
            << "Loading cached library " << path;
        LoadLibrary(path);
        num_loaded++;
        return true;
      });
  return num_loaded;
}

// JIT compile any already lifted bitcode.
void CodeCacheImpl::ReloadLibraries(void) {
  remill::ForEachFileInDirectory(Workspace::BitcodeDir(),
      [this] (const std::string &path) {
        std::unique_ptr<llvm::Module> module(
            remill::LoadModuleFromFile(context.get(), path, true));

        if (module) {
          LOG(INFO)
              << "JIT compiling already lifted code from " << path;
          AddModuleToCache(module);
        } else {
          LOG(ERROR)
              << "Could not load already lifted bitcode module from " << path;
          remill::RemoveFile(path);
        }
        return true;
      });
}

static std::string ModuleTailName(const std::unique_ptr<llvm::Module> &module) {
  auto name = remill::ModuleName(module);
  std::reverse(name.begin(), name.end());
  auto pos = name.find(remill::PathSeparator()[0]);
  if (std::string::npos != pos) {
    name = name.substr(0, pos);
  }
  std::reverse(name.begin(), name.end());
  return name;
}

// Reoptimize the module `module` after it has been instrumented by a tool.
void CodeCacheImpl::ReoptimizeModule(
    const std::unique_ptr<llvm::Module> &module) {
  llvm::Module::iterator func_it;
  llvm::Module::iterator func_it_end;

  auto init = false;
  auto func_generator = [&] (void) -> llvm::Function * {
    if (!init) {
      func_it = module->begin();
      func_it_end = module->end();
      init = true;
    }
    if (func_it == func_it_end) {
      return nullptr;
    } else {
      return &*func_it++;
    }
  };

  OptimizeModule(module.get(), func_generator);
//  auto undef_taint = llvm::UndefValue::get(llvm::Type::getInt1Ty(module->getContext()));
//  for (auto user : undef_taint->users()) {
//    if (auto inst = llvm::dyn_cast<llvm::Instruction>(user)) {
//      LOG(ERROR) << remill::LLVMThingToString(inst);
//      inst->getParent()->dump();
//    }
//  }
}

// Tell the tool to instrument each lifted function.
void CodeCacheImpl::InstrumentTraces(
    const std::unique_ptr<llvm::Module> &module) {

  tool->PrepareModule(module.get());

  std::vector<llvm::Function *> funcs;
  funcs.reserve(module->getFunctionList().size());

  for (auto &func : *module) {
    if (!func.isDeclaration()) {
      funcs.push_back(&func);
    }
  }

  auto changed = false;
  auto md_id = context->getMDKindID("PC");
  for (auto func : funcs) {
    auto node = func->getMetadata(md_id);
    if (!node) {
      continue;
    }

    auto pc_ci = llvm::mdconst::extract<llvm::ConstantInt>(node->getOperand(0));
    if (!pc_ci) {
      LOG(FATAL)
          << "Couldn't extract PC metadata from lifted trace function";
    } else {
      auto pc = pc_ci->getZExtValue();
      changed = tool->InstrumentTrace(func, pc) || changed;
    }
  }

  if (changed) {
    ReoptimizeModule(module);
  }
}

// Load a JIT-compiled library.
void CodeCacheImpl::AddModuleToCache(
    const std::unique_ptr<llvm::Module> &module) {

  InstrumentTraces(module);

  std::stringstream lib_ss;
  lib_ss << Workspace::LibraryDir() << remill::PathSeparator()
         << ModuleTailName(module) << ".obj";

  auto lib_path = lib_ss.str();
  compiler.CompileModuleToFile(*module, lib_path);

  LoadLibrary(lib_path);
  pending_loader.reset();
}

LiftedFunction *CodeCacheImpl::Lookup(TraceId trace_id) const {
  auto entry_it = lifted_functions.find(trace_id);
  if (likely(entry_it != lifted_functions.end())) {
    return entry_it->second;
  } else {
    return nullptr;
  }
}

uintptr_t CodeCacheImpl::Lookup(const char *symbol) {
  std::string name(symbol);
  llvm::JITSymbol sym = findSymbolInLogicalDylib(name);
#ifdef __APPLE__
  if (!sym) {
    sym = findSymbolInLogicalDylib('_' + name);
  }
#endif
  if (!sym) {
    sym = findSymbol(name);
  }
  if (!sym) {
    return 0;
  }
  return sym.getAddress() IF_LLVM_GTE_500(.get());
}

}  // namespace

CodeCache::CodeCache(void) { }

std::unique_ptr<CodeCache> CodeCache::Create(
    std::unique_ptr<Tool> tool_,
    const std::shared_ptr<llvm::LLVMContext> &context_) {
  return std::unique_ptr<CodeCache>(
      new CodeCacheImpl(std::move(tool_), context_));
}

CodeCache::~CodeCache(void) {}

}  // namespace vmill
