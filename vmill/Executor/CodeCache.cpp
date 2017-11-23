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
#include <vector>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <unordered_map>

#include <llvm/IR/Module.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBuffer.h>

#include "remill/BC/Compat/Error.h"
#include "remill/BC/Compat/RuntimeDyld.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

#include "vmill/BC/Compiler.h"
#include "vmill/Executor/CodeCache.h"
#include "vmill/Program/AddressSpace.h"
#include "vmill/Util/AreaAllocator.h"
#include "vmill/Util/Compiler.h"
#include "vmill/Workspace/Workspace.h"

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
};

class CodeCacheImpl : public CodeCache,
                      public llvm::RuntimeDyld::MemoryManager,
                      public llvm::JITSymbolResolver {
 public:
  explicit CodeCacheImpl(const std::shared_ptr<llvm::LLVMContext> &context_);

  virtual ~CodeCacheImpl(void);

  LiftedFunction *Lookup(TraceId trace_id) const override;

  uintptr_t Lookup(const char *symbol) override;

  // Load the runtime library, this must be done first, as it supported all
  // lifted code execution.
  void LoadRuntimeLibrary(void);

  // Load a JIT-compiled module from a file `path`.
  void LoadLibrary(const std::string &path);

  // Load all JIT-compiled modules from the libraries directory. Returns the
  // number of loaded libraries.
  int LoadLibraries(void);

  // JIT compile any already lifted bitcode.
  void ReloadLibraries(void);

  // Implementing the `CodeCache` interface. This takes ownership of the
  // module.
  void AddModuleToCache(const std::unique_ptr<llvm::Module> &module) override;

  // Implementing the `llvm::RuntimeDyld::MemoryManager` interface:

  // Allocate memory for a code section.
  uint8_t *allocateCodeSection(uintptr_t size, unsigned alignment,
                               unsigned section_id, llvm::StringRef) override;

  /// Allocate memory for a data section.
  uint8_t *allocateDataSection(uintptr_t size, unsigned alignment,
                               unsigned section_id, llvm::StringRef,
                               bool is_read_only) override;

  // Ignore exception handling in JITed code. It shouldn't happen
  void registerEHFrames(uint8_t *, uint64_t, size_t) override {}
  void deregisterEHFrames(
      IF_LLVM_LT(5, 0, uint8_t *, uint64_t, size_t)) override {}

  // Apply all final permissions to any pending JITed page ranges, moving
  // them into the `jit_ranges` list.
  bool finalizeMemory(std::string *error_message=nullptr) override;

  // Implementing the `llvm::JITSymbolResolver` interface.

  // Resolve symbols, including hidden symbols, for handling relocations.
  llvm::JITSymbol findSymbolInLogicalDylib(const std::string &name) override;

  /// Resolve external/exported symbols during linking.
  llvm::JITSymbol findSymbol(const std::string &name) override;

 private:
  CodeCacheImpl(void) = delete;

  const std::shared_ptr<llvm::LLVMContext> &context;

  Compiler compiler;
  AreaAllocator code_allocator;
  AreaAllocator data_allocator;
  AreaAllocator index_allocator;

  std::vector<MemoryMap> jit_ranges;
  std::unordered_map<unsigned, MemoryMap> pending_jit_ranges;
  std::unique_ptr<llvm::RuntimeDyld> pending_loader;
  std::unique_ptr<llvm::RuntimeDyld> runtime_loader;

  std::unordered_map<TraceId, LiftedFunction *> lifted_functions;
};

CodeCacheImpl::CodeCacheImpl(const std::shared_ptr<llvm::LLVMContext> &context_)
    : CodeCache(),
      context(context_),
      compiler(context_),
      code_allocator(kAreaRWX, kAreaCodeCacheCode),
      data_allocator(kAreaRW, kAreaCodeCacheData),
      index_allocator(kAreaRW, kAreaCodeCacheIndex) {
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
                   section_id, true, false, true, false};
  pending_jit_ranges[section_id] = map;
  return map.base;
}

// Allocate memory for a code section.
uint8_t *CodeCacheImpl::allocateDataSection(
    uintptr_t size, unsigned alignment, unsigned section_id,
    llvm::StringRef name, bool is_read_only) {
  uint8_t *base = nullptr;
  bool is_index = false;

  // If we're allocating translations then we want all entries across all
  // translation segments to be contiguous.
  if (name == ".translations") {
    base = index_allocator.Allocate(size, 0);
    is_index = true;
  } else {
    base = data_allocator.Allocate(size, alignment);
  }
  MemoryMap map = {base, size, section_id, true, !is_read_only,
                   false, is_index};
  pending_jit_ranges[section_id] = map;
  return map.base;
}

// Normally this function is meant to finalize permissions of any pending JITed
// page ranges. We this as the place to
bool CodeCacheImpl::finalizeMemory(std::string *error_message) {
  jit_ranges.reserve(jit_ranges.size() + pending_jit_ranges.size());
  for (const auto &entry : pending_jit_ranges) {
    const auto &range = entry.second;
    jit_ranges.push_back(range);

    if (!range.is_index) {
      continue;
    }

    auto base = reinterpret_cast<CacheIndexEntry *>(range.base);
    auto limit = &(base[range.size / sizeof(CacheIndexEntry)]);

    for (; base < limit; ++base) {
      if (!code_allocator.Contains(base->lifted_function)) {
        *error_message = "Lifted function address is not managed by the "
                         "code cache allocator.";
        return false;
      }

      auto &lifted_func = lifted_functions[base->trace_id];
      if (lifted_func != nullptr) {
        LOG(ERROR)
            << "Code at " << reinterpret_cast<void *>(base->lifted_function)
            << " implementing trace with hash ("
            << static_cast<TraceHashBaseType>(base->trace_id.hash1) << ", "
            << static_cast<TraceHashBaseType>(base->trace_id.hash2)
            << ") already implemented at " << lifted_func << std::dec;
      } else {
        lifted_func = base->lifted_function;
      }
    }
  }
  pending_jit_ranges.clear();
  return true;
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
  uint64_t addr = llvm::RTDyldMemoryManager::getSymbolAddressInProcess(name);
  if (!addr) {
    LOG(ERROR)
        << "Could not locate symbol " << name;
  }
  return llvm::JITSymbol(addr, llvm::JITSymbolFlags::None);
}

// Load the runtime library, this must be done first, as it supported all
// lifted code execution.
void CodeCacheImpl::LoadRuntimeLibrary(void) {
  auto library_path = Workspace::RuntimeLibraryPath();

  if (!remill::FileExists(library_path)) {
    auto bitcode_path = Workspace::RuntimeBitcodePath();
    DLOG(INFO)
        << "Loading runtime library bitcode " << bitcode_path;

    std::unique_ptr<llvm::Module> runtime(remill::LoadModuleFromFile(
        context.get(), bitcode_path));

    DLOG(INFO)
        << "JIT-compiling runtime library bitcode " << bitcode_path;
    compiler.CompileModuleToFile(*runtime, library_path);
  }

  DLOG(INFO)
      << "Loading runtime library object code " << library_path;
  LoadLibrary(library_path);

  runtime_loader.swap(pending_loader);
}

// Load a JIT-compiled module from a file `path`.
void CodeCacheImpl::LoadLibrary(const std::string &path) {
  pending_loader.reset(new llvm::RuntimeDyld(*this, *this));

  auto maybe_buff_ptr = llvm::MemoryBuffer::getFile(
      path, -1 /* FileSize */, false /* RequiresNullTerminator */);
  if (remill::IsError(maybe_buff_ptr)) {
    LOG(FATAL)
        << "Unable to open shared library " << path << ": "
        << remill::GetErrorString(maybe_buff_ptr);
  }

  auto &buff_ptr = remill::GetReference(maybe_buff_ptr);
  auto maybe_obj_file_ptr = llvm::object::ObjectFile::createObjectFile(
      *buff_ptr);

  if (remill::IsError(maybe_obj_file_ptr)) {
    LOG(FATAL)
        << "Unable to load " << path << " as an object file: "
        << remill::GetErrorString(maybe_obj_file_ptr);
  }

  auto &object_file_ptr = remill::GetReference(maybe_obj_file_ptr);
  auto info = pending_loader->loadObject(*object_file_ptr);
  if (!info) {
    if (pending_loader->hasError()) {
      LOG(FATAL)
          << "Unable to load " << path << " as an object file: "
          << pending_loader->getErrorString().str();
    }
  }

  pending_loader->resolveRelocations();
  std::string error;
  CHECK(finalizeMemory(&error))
      << "Unable to finalize JITed code memory: " << error;

  // TODO(pag): Is the library's `_start` function called?
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

// Load a JIT-compiled library.
void CodeCacheImpl::AddModuleToCache(
    const std::unique_ptr<llvm::Module> &module) {
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
  if (!sym) {
    sym = findSymbol(name);
  }

  return sym.getAddress();
}

}  // namespace

CodeCache::CodeCache(void) { }

std::unique_ptr<CodeCache> CodeCache::Create(
    const std::shared_ptr<llvm::LLVMContext> &context_) {
  return std::unique_ptr<CodeCache>(new CodeCacheImpl(context_));
}

CodeCache::~CodeCache(void) {}

}  // namespace vmill
