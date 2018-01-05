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

#include "remill/OS/FileSystem.h"
#include "vmill/Workspace/Tool.h"

#include "tools/dft/DataFlowTracker.h"

namespace vmill {

Tool::Tool(void) {}

Tool::~Tool(void) {}

// Called when lifted bitcode or the runtime needs to resolve an external
// symbol.
uint64_t Tool::FindSymbolForLinking(const std::string &, uint64_t resolved) {
  return resolved;
}

// Called just before the beginning of a run.
void Tool::SetUp(void) {}

// Called just after the ending of a run.
void Tool::TearDown(void) {}

bool Tool::InstrumentRuntime(llvm::Module *) {
  return false;
}

bool Tool::InstrumentTrace(llvm::Function *, uint64_t) {
  return false;
}

std::unique_ptr<Tool> Tool::Load(const std::string &name_or_path) {
  if (name_or_path == "null") {
    return std::unique_ptr<Tool>(new NullTool);

  } else if (name_or_path == "dft") {
    return CreateDataFlowTracker();

  } else if (remill::FileExists(name_or_path)) {
    LOG(FATAL)
        << "Dynamically loaded tools are not yet supported.";

  } else {
    LOG(FATAL)
        << "Cannot load the " << name_or_path << " instrumentation tool.";
    return std::unique_ptr<Tool>(nullptr);
  }
}

NullTool::~NullTool(void) {}

ProxyTool::ProxyTool(std::unique_ptr<Tool> tool_)
    : tool(std::move(tool_)) {}

ProxyTool::~ProxyTool(void) {}

// Called when lifted bitcode or the runtime needs to resolve an external
// symbol.
uint64_t ProxyTool::FindSymbolForLinking(
    const std::string &name, uint64_t resolved) {
  return tool->FindSymbolForLinking(name, resolved);
}

// Instrument the runtime module.
bool ProxyTool::InstrumentRuntime(llvm::Module *module) {
  return tool->InstrumentRuntime(module);
}

// Instrument a lifted function/trace.
bool ProxyTool::InstrumentTrace(llvm::Function *func, uint64_t pc) {
  return tool->InstrumentTrace(func, pc);
}

}  // namespace vmill
