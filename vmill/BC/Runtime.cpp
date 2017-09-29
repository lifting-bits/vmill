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

#include <llvm/IR/Module.h>

#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

#include "vmill/BC/Runtime.h"

#ifndef VMILL_BUILD_RUNTIME_DIR
# error "`VMILL_BUILD_RUNTIME_DIR` must be set."
# define VMILL_BUILD_RUNTIME_DIR
#endif  // VMILL_BUILD_RUNTIME_DIR

#ifndef VMILL_INSTALL_RUNTIME_DIR
# error "`VMILL_INSTALL_RUNTIME_DIR` must be defined."
# define VMILL_INSTALL_RUNTIME_DIR
#endif  // VMILL_INSTALL_RUNTIME_DIR

DECLARE_string(arch);
DECLARE_string(os);
DECLARE_string(workspace);

DEFINE_string(runtime, "", "Name of a runtime, or absolute path to a "
                           "runtime bitcode file.");

namespace vmill {
namespace {

// Get the path to the runtime file.
static std::string GetRuntimeFile(void) {

  std::string search_paths[] = {
      "",  // If it's an absolute path.
      remill::CurrentWorkingDirectory() + "/",
      FLAGS_workspace + "/",
      VMILL_BUILD_RUNTIME_DIR "/",
      VMILL_INSTALL_RUNTIME_DIR "/",
  };

  if (FLAGS_runtime.empty()) {
    FLAGS_runtime = FLAGS_os + "_" + FLAGS_arch;
  }

  for (auto runtime_dir : search_paths) {
    std::stringstream ss;
    ss << runtime_dir << FLAGS_runtime;
    auto runtime_path = ss.str();
    if (remill::FileExists(runtime_path)) {
      return runtime_path;
    }

    ss << ".bc";
    runtime_path = ss.str();
    if (remill::FileExists(runtime_path)) {
      return runtime_path;
    }
  }

  LOG(FATAL)
      << "Cannot find path to runtime for " << FLAGS_os
      << " and " << FLAGS_arch;

  return "";
}

}  // namespace

std::unique_ptr<llvm::Module> LoadTargetRuntime(
    const std::shared_ptr<llvm::LLVMContext> &context) {
  auto file_name = GetRuntimeFile();
  LOG(INFO)
      << "Loading target " << FLAGS_arch << " runtime for OS " << FLAGS_os
      << " from " << file_name;

  return std::unique_ptr<llvm::Module>(
      remill::LoadModuleFromFile(context.get(), file_name));
}

}  // namespace vmill
