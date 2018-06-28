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

#include <cstdlib>
#include <fcntl.h>
#include <sstream>
#include <unistd.h>

#include <llvm/Object/ObjectFile.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/Program/Snapshot.h"
#include "vmill/Workspace/Workspace.h"

#include "third_party/ELFIO/elfio/elfio.hpp"

#include "remill/Arch/X86/Runtime/State.h"

DEFINE_string(binary, "", "ELF binary to load into a snapshot.");
DECLARE_string(arch);
DECLARE_string(os);

DEFINE_bool(verbose, false, "Enable verbose logging?");

namespace {

}  // namespace

int main(int argc, char **argv) {
  FLAGS_logtostderr = 1;
  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --binary ELF_BIN \\" << std::endl
     << "    --workspace WORKSPACE_DIR" << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

  ELFIO::elfio reader;
  if (!reader.load(FLAGS_binary)) {
    LOG(ERROR)
        << "Could not load ELF binary " << FLAGS_binary;
    return EXIT_FAILURE;
  }
  CHECK_EQ(reader.get_class(), ELFCLASS32);

  auto arch = remill::GetTargetArch();
  CHECK_EQ(arch->os_name, remill::kOSVxWorks);
  CHECK_EQ(arch->address_size, 32);

  vmill::snapshot::Program snapshot;
  snapshot.set_arch(FLAGS_arch);
  snapshot.set_os(FLAGS_os);

  auto memory = snapshot.add_address_spaces();
  memory->set_id(1);

  uint64_t text_begin = 0;

  for (auto seg : reader.segments) {
    const auto base = seg->get_virtual_address() & ~4095ULL;
    const auto start = seg->get_virtual_address() & 4095ULL;
    const auto size = (start + seg->get_memory_size() + 4095ULL) & ~4095ULL;
    const auto info = memory->add_page_ranges();

    if (base <= reader.get_entry() && reader.get_entry() < (base + size)) {
      text_begin = base;
    }

    std::stringstream name_ss;
    name_ss << "seg_" << std::hex << base << "_" << (base + size);
    const auto name = name_ss.str();

    std::stringstream dest_path_ss;
    dest_path_ss << vmill::Workspace::MemoryDir()
                 << remill::PathSeparator()
                 << name;
    const auto dest_path = dest_path_ss.str();

    // Make sure the file that will contain the memory has the right size.
    auto dest_fd = open(dest_path.c_str(), O_RDWR | O_TRUNC | O_CREAT, 0666);
    CHECK(-1 != dest_fd)
        << "Can't open " << dest_path << " for writing.";

    info->set_base(static_cast<int64_t>(base));
    info->set_limit(static_cast<int64_t>(base + size));
    info->set_can_read(!!(PF_R & seg->get_flags()));
    info->set_can_write(!!(PF_W & seg->get_flags()));
    info->set_can_exec(!!(PF_X & seg->get_flags()));
    info->set_kind(vmill::snapshot::kAnonymousPageRange);
    info->set_name(name);
    LOG(INFO)
        << std::hex << "Copying range [" << base << ", "
        << (base + size) << std::dec << ")";

    auto data = new char[size];
    memset(data, 0, size);
    memcpy(&(data[start]), seg->get_data(), seg->get_file_size());

    // Load data in.
    auto written = 0ULL;
    while (written < size) {
      auto ret = write(dest_fd, &(data[written]), size - written);
      auto err = errno;
      if (ret >= 0) {
        written += static_cast<uint64_t>(ret);
      } else {
        LOG(ERROR)
            << "Error copying memory to " << dest_path << ": " << strerror(err);
      }
    }

    close(dest_fd);
  }

  CHECK(0 != text_begin);

  auto state = new X86State;
  state->gpr.rax.qword = 0;
  state->gpr.rbx.qword = 0x2;
  state->gpr.rcx.qword = 0;
  state->gpr.rdx.qword = 0x0015b878;
  state->gpr.rsp.dword = 0x00107fc8;
  state->gpr.rbp.dword = 0x00107ff4;
  state->gpr.rsi.dword = static_cast<uint32_t>(reader.get_entry());
  state->gpr.rdi.dword = 0x00008000;
  state->gpr.rip.dword = static_cast<uint32_t>(text_begin);

  std::string state_str;
  state_str.insert(state_str.end(), reinterpret_cast<char *>(state),
                   reinterpret_cast<char *>(&(state[1])));

  auto task = snapshot.add_tasks();
  task->set_pc(static_cast<int64_t>(state->gpr.rip.dword));
  task->set_state(state_str);
  task->set_address_space_id(1);

  const auto &path = vmill::Workspace::SnapshotPath();
  std::ofstream snaphot_out(path);
  CHECK(snaphot_out)
      << "Unable to open " << path << " for writing";

  CHECK(snapshot.SerializePartialToOstream(&snaphot_out))
      << "Unable to serialize snapshot description to " << path;

  return EXIT_SUCCESS;
}
