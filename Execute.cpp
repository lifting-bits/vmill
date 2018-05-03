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

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/ManagedStatic.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/BC/Lifter.h"
#include "vmill/BC/Util.h"
#include "vmill/Executor/CodeCache.h"
#include "vmill/Executor/Executor.h"
#include "vmill/Program/AddressSpace.h"
#include "vmill/Program/Snapshot.h"
#include "vmill/Workspace/Workspace.h"

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_uint64(max_num_execs, 1,
              "Maximum number of times to execute the program.");

int main(int argc, char **argv) {

  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    [--tool TOOL_NAME_OR_PATH] \\" << std::endl
     << "    [--workspace WORKSPACE_DIR]" << std::endl
     << "    [--runtime RUNTIME_PATH]" << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_logtostderr = true;
  CHECK(0 < FLAGS_max_num_execs)
      << "Must specific a positive value for `--max_num_execs`.";

  CHECK(FLAGS_arch.empty() && FLAGS_os.empty())
      << "The architecture and OS names must NOT be manually specified.";

  auto snapshot = vmill::LoadSnapshotFromFile(vmill::Workspace::SnapshotPath());

  // Take the target architecture from the snapshot file.
  FLAGS_arch = snapshot->arch();
  const auto arch_name = remill::GetArchName(FLAGS_arch);
  CHECK(remill::kArchInvalid != arch_name)
      << "Snapshot file corrupted; invalid architecture " << FLAGS_arch;

  // Take the target OS from the snapshot file.
  FLAGS_os = snapshot->os();
  const auto os_name = remill::GetOSName(FLAGS_os);
  CHECK(remill::kOSInvalid != os_name)
      << "Snapshot file corrupted; invalid OS " << FLAGS_os;

  vmill::Executor executor;
  vmill::Workspace::LoadSnapshotIntoExecutor(snapshot, executor);

  for (uint64_t i = 0; i < FLAGS_max_num_execs; ++i) {
    executor.Run();
  }

  llvm::llvm_shutdown();
  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}
