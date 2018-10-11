/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/mman.h>
#include <unistd.h>

#include <llvm/ADT/Triple.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/MemoryBuffer.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

#include "remill/BC/Compat/Error.h"
#include "remill/BC/Compat/RuntimeDyld.h"
#include "remill/BC/Compat/JITSymbol.h"

#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/Program/Snapshot.h"
#include "vmill/Workspace/Workspace.h"

#include "remill/Arch/X86/Runtime/State.h"

DEFINE_string(binary, "", "Binary to load into a snapshot.");
DECLARE_string(arch);
DECLARE_string(os);

DEFINE_bool(verbose, false, "Enable verbose logging?");

namespace {

class Loader : public llvm::RuntimeDyld::MemoryManager,
               public llvm::JITSymbolResolver,
               public llvm::RuntimeDyld {
 public:
  virtual ~Loader(void) = default;

  Loader(vmill::snapshot::AddressSpace *addr_space_)
      : llvm::RuntimeDyld::MemoryManager(),
        llvm::JITSymbolResolver(),
        llvm::RuntimeDyld(*this, *this),
        addr_space(addr_space_) {}

  // Map a section. This creates a memory-mapped file into which the loader
  // will place the actual data, and it also adds an entry to the page range
  // info of the address space.
  uint8_t *MapSection(unsigned sec_id, const std::string &sec_name,
                      uintptr_t size, bool can_write, bool can_exec) {
    std::stringstream name_ss;
    name_ss << "sec_" << sec_id;
    for (auto c : sec_name) {
      if (isalnum(c) || '.' == c) {
        name_ss << c;
      } else {
        name_ss << '_';
      }
    }
    const auto name = name_ss.str();

    auto info = addr_space->add_page_ranges();
    info->set_can_read(true);
    info->set_can_write(can_write);
    info->set_can_exec(can_exec);
    info->set_kind(vmill::snapshot::kAnonymousPageRange);
    info->set_name(name);
    ranges[sec_id] = info;

    std::stringstream dest_path_ss;
    dest_path_ss << vmill::Workspace::MemoryDir()
                 << remill::PathSeparator()
                 << name;
    const auto dest_path = dest_path_ss.str();

    // Make a new file that will hold whatever gets put into this mapped range.
    auto fd = open(dest_path.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0666);
    auto err = errno;
    CHECK(fd != -1)
        << "Unable to create " << dest_path << ": " << strerror(err);

    size += 4095;
    size &= ~4095ULL;

    range_size[sec_id] = static_cast<int64_t>(size);

    // Make sure the file is at least big enough to hold everything, and is
    // a multiple of the page size.
    auto ret = ftruncate(fd, size);
    err = errno;
    CHECK(ret != -1)
        << "Unable to scale file " << dest_path << " to " << size << " bytes: "
        << strerror(err);

    // Map the file into memory, so that LLVM's loading and relocation stuff
    // can write bytes into it.
    auto addr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_FILE, fd, 0);
    err = errno;
    CHECK(addr != MAP_FAILED)
        << "Unable to memory map " << dest_path << ": " << strerror(err);

    return reinterpret_cast<uint8_t *>(addr);
  }

  // Implementing the `llvm::RuntimeDyld::MemoryManager` interface:

  // Allocate memory for a code section.
  uint8_t *allocateCodeSection(
      uintptr_t size, unsigned alignment,
      unsigned section_id, llvm::StringRef name) final {
    auto name_str = name.str();
    LOG(INFO)
        << "Allocating code section " << name_str << " with "
        << size << " bytes and alignment " << alignment;
    return MapSection(section_id, name_str, size, false, true);
  }

  /// Allocate memory for a data section.
  uint8_t *allocateDataSection(
      uintptr_t size, unsigned alignment,
      unsigned section_id, llvm::StringRef name,
      bool is_read_only) final {
    auto name_str = name.str();
    LOG(INFO)
        << "Allocating data section " << name_str << " with "
        << size << " bytes and alignment " << alignment;
    return MapSection(section_id, name_str, size, !is_read_only, false);
  }

  // Register exception handling frames.
  void registerEHFrames(uint8_t *, uint64_t, size_t) final {}

  // We never unload JITed code.
  void deregisterEHFrames(
      IF_LLVM_LT(5, 0, uint8_t *, uint64_t, size_t)) final {}

  // Apply all final permissions to any pending JITed page ranges, moving
  // them into the `jit_ranges` list.
  bool finalizeMemory(std::string *error_message=nullptr) final {
    (void) error_message;
    return true;
  }

  // Implementing the `llvm::JITSymbolResolver` interface.

  // Resolve symbols, including hidden symbols, for handling relocations.
  llvm::JITSymbol findSymbolInLogicalDylib(const std::string &name) final {
    return this->llvm::RuntimeDyld::getSymbol(name);
  }

  /// Resolve external/exported symbols during linking.
  llvm::JITSymbol findSymbol(const std::string &name) final {
    return nullptr;
  }

 private:
  Loader(void) = delete;

  vmill::snapshot::AddressSpace * const addr_space;

 public:
  std::unordered_map<unsigned, vmill::snapshot::PageRange *> ranges;
  std::unordered_map<unsigned, int64_t> range_size;
};

class HackLoadedObjectInfo : public llvm::RuntimeDyld::LoadedObjectInfo {
 public:
  virtual ~HackLoadedObjectInfo(void) = default;
  using llvm::RuntimeDyld::LoadedObjectInfo::LoadedObjectInfo;
  using llvm::RuntimeDyld::LoadedObjectInfo::ObjSecToIDMap;
};

}  // namespace

int main(int argc, char **argv) {
  FLAGS_logtostderr = 1;
  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --binary BINARY \\" << std::endl
     << "    --workspace WORKSPACE_DIR" << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

  // Make sure the workspace directory exists.
  (void) vmill::Workspace::Dir();
  (void) vmill::Workspace::MemoryDir();

  if (FLAGS_binary.empty()) {
    LOG(ERROR)
        << "Must provide a path to a binary using --binary";
    return EXIT_FAILURE;
  }

  // Open the file.
  auto maybe_file_buff = llvm::MemoryBuffer::getFile(FLAGS_binary);
  if (remill::IsError(maybe_file_buff)) {
    auto error_string = remill::GetErrorString(maybe_file_buff);
    LOG(ERROR)
        << "Could not read binary " << FLAGS_binary << ": " << error_string;
    return EXIT_FAILURE;
  }

  // Parse it as an object file of some unknown format.
  auto &file_buff = remill::GetReference(maybe_file_buff);
  auto maybe_obj_file = llvm::object::ObjectFile::createObjectFile(
      file_buff->getMemBufferRef());
  if (remill::IsError(maybe_obj_file)) {
    auto error_string = remill::GetErrorString(maybe_obj_file);
    LOG(ERROR)
        << "Could not parse binary " << FLAGS_binary << ": " << error_string;
    return EXIT_FAILURE;
  }

  auto &obj_file = remill::GetReference(maybe_obj_file);
  auto arch_name = remill::kArchInvalid;
  auto os_name = remill::kOSInvalid;
  auto llvm_arch_name = static_cast<llvm::Triple::ArchType>(
      obj_file->getArch());

  // Infer the arch type, and allow the command-line --arch to specialize
  // which subset of the arch we are dealing with.
  switch (llvm_arch_name) {
    case llvm::Triple::aarch64:
      if (!FLAGS_arch.empty() && FLAGS_arch != "aarch64") {
        LOG(ERROR)
            << "File " << FLAGS_binary << " is an aarch64 binary, but the "
            << "provided architecture to --arch was " << FLAGS_arch;
        return EXIT_FAILURE;
      }
      arch_name = remill::kArchAArch64LittleEndian;
      break;

    case llvm::Triple::x86:
      if (!FLAGS_arch.empty()) {
        switch (remill::GetArchName(FLAGS_arch)) {
          case remill::kArchX86:
            arch_name = remill::kArchX86;
            break;
          case remill::kArchX86_AVX:
            arch_name = remill::kArchX86_AVX;
            break;
          case remill::kArchX86_AVX512:
            arch_name = remill::kArchX86_AVX512;
            break;
          default:
            LOG(ERROR)
                << "Architecture " << FLAGS_arch
                << " is not part of the 32-bit X86 family.";
            return EXIT_FAILURE;
        }
      } else {
        arch_name = remill::kArchX86_AVX;
      }
      break;

    case llvm::Triple::x86_64:
      if (!FLAGS_arch.empty()) {
        switch (remill::GetArchName(FLAGS_arch)) {
          case remill::kArchAMD64:
            arch_name = remill::kArchAMD64;
            break;
          case remill::kArchAMD64_AVX:
            arch_name = remill::kArchAMD64_AVX;
            break;
          case remill::kArchAMD64_AVX512:
            arch_name = remill::kArchAMD64_AVX512;
            break;
          default:
            LOG(ERROR)
                << "Architecture " << FLAGS_arch
                << " is not part of the AMD64 (64-bit X86) family.";
            return EXIT_FAILURE;
        }
      } else {
        arch_name = remill::kArchAMD64_AVX;
      }
      break;

    default:
      LOG(ERROR)
          << "Unsupported architecture: "
          << llvm::Triple::getArchTypeName(llvm_arch_name).str();
      return EXIT_FAILURE;
  }

  // Infer the OS from the object format.
  if (obj_file->isCOFF()) {
    os_name = remill::kOSWindows;
  } else if (obj_file->isMachO()) {
    os_name = remill::kOSmacOS;
  } else if (obj_file->isELF()) {
    os_name = remill::kOSLinux;
  } else {
    LOG(ERROR)
        << "Unsupported object file format.";
    return EXIT_FAILURE;
  }

  // Make sure it matches up with anything on the command-line.
  if (!FLAGS_os.empty() && FLAGS_os != remill::GetOSName(os_name)) {
    LOG(ERROR)
        << "Inferred OS of binary to be " << remill::GetOSName(os_name)
        << " but got " << FLAGS_os << " specified to --os";
    return EXIT_FAILURE;
  }

  FLAGS_arch = remill::GetArchName(arch_name);
  FLAGS_os = remill::GetOSName(os_name);

  auto arch = remill::Arch::Get(os_name, arch_name);
  if (!arch) {
    LOG(ERROR)
        << "Unsupported OS/architecture combination: "
        << remill::GetOSName(os_name) << " and "
        << remill::GetArchName(arch_name);
    return EXIT_FAILURE;
  }

  LOG(INFO)
      << "Loading binary " << FLAGS_binary << " with architecture "
      << FLAGS_arch << " and OS model for " << FLAGS_os;

  vmill::snapshot::Program snapshot;
  snapshot.set_arch(FLAGS_arch);
  snapshot.set_os(FLAGS_os);

  auto memory = snapshot.add_address_spaces();
  memory->set_id(1);

#ifndef NDEBUG
  llvm::setCurrentDebugType("dyld");
#endif

  // Try to load the file.
  Loader loader(memory);
  loader.setProcessAllSections(true);

  auto obj_file_info = loader.loadObject(*obj_file);
  if (!obj_file_info) {
    LOG(ERROR)
        << "Unable to load object file " << FLAGS_binary;
    return EXIT_FAILURE;
  }

  // Something went wrong.
  if (loader.hasError()) {
    LOG(ERROR)
        << "Unable to load object file " << FLAGS_binary
        << ": " << loader.getErrorString().str();
    return EXIT_FAILURE;
  }

  // Finalize all memory stuff.
  loader.finalizeWithMemoryManagerLocking();

  // Something went wrong.
  if (loader.hasError()) {
    LOG(ERROR)
        << "Unable to finalize loaded object file " << FLAGS_binary
        << ": " << loader.getErrorString().str();
    return EXIT_FAILURE;
  }

  auto &hack_info = *reinterpret_cast<HackLoadedObjectInfo *>(
      obj_file_info.get());

  // Fix up the snapshot with where the sections actually go in memory.
  for (auto &entry : hack_info.ObjSecToIDMap) {
    auto &sec = entry.first;
    auto sec_id = entry.second;
    auto load_addr = obj_file_info->getSectionLoadAddress(sec);
    if (!load_addr) {
      continue;
    }

    llvm::StringRef sec_name_ref;
    (void) sec.getName(sec_name_ref);
    std::string sec_name = sec_name_ref.str();

    LOG(INFO)
        << "Section " << sec_name << " with ID " << sec_id << " loaded at "
        << std::hex << load_addr << std::dec;

    auto size = sec.getSize();
    size += 4095;
    size &= ~4095ULL;

    auto info = loader.ranges[sec_id];
    if (!info) {
      LOG(WARNING)
          << "Loaded section " << sec_name << " with ID " << sec_id
          << " is not associated with any range";
      continue;
    }
    info->set_base(static_cast<int64_t>(load_addr));
    info->set_limit(info->base() + loader.range_size[sec_id]);
  }

//  uint64_t text_begin = 0;
//
//  for (auto seg : reader.segments) {
//    const auto base = seg->get_virtual_address() & ~4095ULL;
//    const auto start = seg->get_virtual_address() & 4095ULL;
//    const auto size = (start + seg->get_memory_size() + 4095ULL) & ~4095ULL;
//    const auto info = memory->add_page_ranges();
//
//    if (base <= reader.get_entry() && reader.get_entry() < (base + size)) {
//      text_begin = base;
//    }
//

//
//    // Make sure the file that will contain the memory has the right size.
//    auto dest_fd = open(dest_path.c_str(), O_RDWR | O_TRUNC | O_CREAT, 0666);
//    CHECK(-1 != dest_fd)
//        << "Can't open " << dest_path << " for writing.";
//

//    LOG(INFO)
//        << std::hex << "Copying range [" << base << ", "
//        << (base + size) << std::dec << ")";
//
//    auto data = new char[size];
//    memset(data, 0, size);
//    memcpy(&(data[start]), seg->get_data(), seg->get_file_size());
//
//    // Load data in.
//    auto written = 0ULL;
//    while (written < size) {
//      auto ret = write(dest_fd, &(data[written]), size - written);
//      auto err = errno;
//      if (ret >= 0) {
//        written += static_cast<uint64_t>(ret);
//      } else {
//        LOG(ERROR)
//            << "Error copying memory to " << dest_path << ": " << strerror(err);
//      }
//    }
//
//    close(dest_fd);
//  }
//
//  CHECK(0 != text_begin);
//
//  auto state = new X86State;
//  state->gpr.rax.qword = 0;
//  state->gpr.rbx.qword = 0x2;
//  state->gpr.rcx.qword = 0;
//  state->gpr.rdx.qword = 0x0015b878;
//  state->gpr.rsp.dword = 0x00107fc8;
//  state->gpr.rbp.dword = 0x00107ff4;
//  state->gpr.rsi.dword = static_cast<uint32_t>(reader.get_entry());
//  state->gpr.rdi.dword = 0x00008000;
//  state->gpr.rip.dword = static_cast<uint32_t>(text_begin);
//
//  std::string state_str;
//  state_str.insert(state_str.end(), reinterpret_cast<char *>(state),
//                   reinterpret_cast<char *>(&(state[1])));
//
//  auto task = snapshot.add_tasks();
//  task->set_pc(static_cast<int64_t>(state->gpr.rip.dword));
//  task->set_state(state_str);
//  task->set_address_space_id(1);

  const auto &path = vmill::Workspace::SnapshotPath();
  std::ofstream snaphot_out(path);
  CHECK(snaphot_out)
      << "Unable to open " << path << " for writing";

  CHECK(snapshot.SerializePartialToOstream(&snaphot_out))
      << "Unable to serialize snapshot description to " << path;

  return EXIT_SUCCESS;
}
