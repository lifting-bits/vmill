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

#include <llvm/Support/DynamicLibrary.h>

#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"
#include "vmill/Util/Util.h"
#include "vmill/Workspace/Tool.h"

#include "tools/Fuzzer/Fuzzer.h"
#include "tools/TaintTracker/DataFlowTracker.h"

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

namespace {

static uint64_t StubFindSymbolForLinking(const std::string &,
                                         uint64_t resolved) {
  return resolved;
}

static bool StubInstrumentRuntime(llvm::Module *) {
  return false;
}

static bool StubInstrumentTrace(llvm::Function *, uint64_t) {
  return false;
}

static void StubSetUpTearDown(void) {}

// Kind of like a proxy tool, but for tools implemented as shared libraries.
class SharedLibraryTool : public Tool {
 public:
  explicit SharedLibraryTool(const std::string &path)
      : error(),
        lib(llvm::sys::DynamicLibrary::getPermanentLibrary(
            path.c_str(), &error)),
        find_symbol_for_linking(StubFindSymbolForLinking),
        instrument_runtime(StubInstrumentRuntime),
        instrument_trace(StubInstrumentTrace),
        set_up(StubSetUpTearDown),
        tear_down(StubSetUpTearDown) {

    CHECK(lib.isValid())
        << "Couldn't load " << path << ": " << error;

    auto loc = lib.SearchForAddressOfSymbol("FindSymbolForLinking");
    if (loc) {
      find_symbol_for_linking = \
          reinterpret_cast<decltype(find_symbol_for_linking)>(loc);
    }

    loc = lib.SearchForAddressOfSymbol("InstrumentRuntime");
    if (loc) {
      instrument_runtime = reinterpret_cast<decltype(instrument_runtime)>(loc);
    }

    loc = lib.SearchForAddressOfSymbol("InstrumentTrace");
    if (loc) {
      instrument_trace = reinterpret_cast<decltype(instrument_trace)>(loc);
    }

    loc = lib.SearchForAddressOfSymbol("SetUp");
    if (loc) {
      set_up = reinterpret_cast<decltype(set_up)>(loc);
    }

    loc = lib.SearchForAddressOfSymbol("TearDown");
    if (loc) {
      tear_down = reinterpret_cast<decltype(tear_down)>(loc);
    }
  }

  virtual ~SharedLibraryTool(void) {}

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol.
  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) final {
    return find_symbol_for_linking(name, resolved);
  }

  // Instrument the runtime module.
  bool InstrumentRuntime(llvm::Module *module) final {
    return instrument_runtime(module);
  }

  // Instrument a lifted function/trace.
  bool InstrumentTrace(llvm::Function *func, uint64_t pc) final {
    return instrument_trace(func, pc);
  }

  // Called just before the beginning of a run.
  void SetUp(void) final {
    set_up();
  }

  // Called just after the ending of a run.
  void TearDown(void) final {
    tear_down();
  }

 private:
  std::string error;

  llvm::sys::DynamicLibrary lib;

  uint64_t (*find_symbol_for_linking)(const std::string &, uint64_t);
  bool (*instrument_runtime)(llvm::Module *);
  bool (*instrument_trace)(llvm::Function *, uint64_t);
  void (*set_up)(void);
  void (*tear_down)(void);
};

static std::unique_ptr<Tool> LoadOneTool(const std::string &name_or_path) {
  if (name_or_path == "branch_coverage") {
    return CreateBranchCoverageTracker();

  } else if (name_or_path == "value_coverage") {
    return CreateValueCoverageTracker();

  } else if (name_or_path == "fuzzer") {
    return CreateFuzzer();

  } else if (remill::FileExists(name_or_path)) {
    LOG(INFO)
        << "Loading instrumentation tool from " << name_or_path;
    return std::unique_ptr<Tool>(new SharedLibraryTool(name_or_path));

  } else {
    LOG(FATAL)
        << "Cannot load the " << name_or_path << " instrumentation tool.";
    return std::unique_ptr<Tool>(nullptr);
  }
}

}  // namespace

std::unique_ptr<Tool> Tool::Load(std::string request) {

  if (request.empty()) {
    return std::unique_ptr<Tool>(new NullTool);
  }

  auto tool_names_or_paths = SplitPathList(request);

  if (tool_names_or_paths.empty()) {
    return LoadOneTool(request);

  } else if (1 == tool_names_or_paths.size()) {
    return LoadOneTool(tool_names_or_paths[0]);

  } else {
    auto tool = new CompositorTool;
    for (const auto &tool_name_or_path : tool_names_or_paths) {
      tool->AddTool(LoadOneTool(tool_name_or_path));
    }
    return std::unique_ptr<Tool>(tool);
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

// Called just before the beginning of a run.
void ProxyTool::SetUp(void) {
  tool->SetUp();
}

// Called just after the ending of a run.
void ProxyTool::TearDown(void) {
  tool->TearDown();
}

CompositorTool::~CompositorTool(void) {}

CompositorTool::CompositorTool(std::unique_ptr<Tool> tool) {
  tools.push_back(std::move(tool));
}

void CompositorTool::AddTool(std::unique_ptr<Tool> tool) {
  tools.push_back(std::move(tool));
}

// Called when lifted bitcode or the runtime needs to resolve an external
// symbol.
uint64_t CompositorTool::FindSymbolForLinking(
    const std::string &name, uint64_t resolved) {
  for (auto &tool : tools) {
    resolved = tool->FindSymbolForLinking(name, resolved);
  }
  return resolved;
}

// Instrument the runtime module.
bool CompositorTool::InstrumentRuntime(llvm::Module *module) {
  bool changed = false;
  for (auto &tool : tools) {
    changed = tool->InstrumentRuntime(module) || changed;
  }
  return changed;
}

// Instrument a lifted function/trace.
bool CompositorTool::InstrumentTrace(llvm::Function *func, uint64_t pc) {
  bool changed = false;
  for (auto &tool : tools) {
    changed = tool->InstrumentTrace(func, pc) || changed;
  }
  return changed;
}

// Called just before the beginning of a run.
void CompositorTool::SetUp(void) {
  for (auto &tool : tools) {
    tool->SetUp();
  }
}

// Called just after the ending of a run.
void CompositorTool::TearDown(void) {
  for (size_t i = 1; i <= tools.size(); ++i) {
    tools[tools.size() - i]->TearDown();  // Call in reverse order.
  }
}

}  // namespace vmill
