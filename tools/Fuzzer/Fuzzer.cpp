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

#include <unordered_map>
#include <vector>

#include "tools/Fuzzer/Fuzzer.h"
#include "tools/Fuzzer/Location.h"

#include "vmill/Util/Compiler.h"

namespace vmill {
namespace {

static std::vector<uint64_t> gTakenEdgeCount;
static std::vector<uint64_t> gNotTakenEdgeCount;

static void IncrementEdge(std::vector<uint64_t> &counter, Location edge_loc) {
  auto index = static_cast<size_t>(edge_loc);
  if (unlikely(index >= counter.size())) {
    counter.resize(index + 1U);
  }
  counter[index]++;
}

static void CoverSwitch(Location taken_edge, const Location *edges_begin,
                        const Location *edges_end) {
  for (auto edge_ptr = edges_begin; edge_ptr < edges_end; ++edge_ptr) {
    auto edge = *edge_ptr;
    if (edge == taken_edge) {
      IncrementEdge(gTakenEdgeCount, edge);
    } else {
      IncrementEdge(gNotTakenEdgeCount, edge);
    }
  }
}

static void CoverBranch(Location taken_edge, Location not_taken_edge) {
  IncrementEdge(gTakenEdgeCount, taken_edge);
  IncrementEdge(gNotTakenEdgeCount, not_taken_edge);
}

static void CoverCompare1(Location here, int, uint8_t lhs, uint8_t rhs) {

}

static void CoverCompare2(Location here, int, uint16_t lhs, uint16_t rhs) {

}

static void CoverCompare4(Location here, int, uint32_t lhs, uint32_t rhs) {

}

static void CoverCompare8(Location here, int, uint64_t lhs, uint64_t rhs) {

}

class FuzzerTool : public Tool {
 public:
  virtual ~FuzzerTool(void) {}

  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) override {
    if (name == "__cov_cmp_1") {
      resolved = reinterpret_cast<uintptr_t>(CoverCompare1);
    } else if (name == "__cov_cmp_2") {
      resolved = reinterpret_cast<uintptr_t>(CoverCompare2);
    } else if (name == "__cov_cmp_4") {
      resolved = reinterpret_cast<uintptr_t>(CoverCompare4);
    } else if (name == "__cov_cmp_8") {
      resolved = reinterpret_cast<uintptr_t>(CoverCompare8);
    } else if (name == "__cov_switch") {
      resolved = reinterpret_cast<uintptr_t>(CoverSwitch);
    } else if (name == "__cov_branch") {
      resolved = reinterpret_cast<uintptr_t>(CoverBranch);
    }
    return Tool::FindSymbolForLinking(name, resolved);
  }

  void SetUp(void) final {
    gTakenEdgeCount.clear();
    gNotTakenEdgeCount.clear();
  }

  void TearDown(void) final {
    uint64_t count = 0;
    uint64_t unique_count = 0;
    for (auto edge_count : gTakenEdgeCount) {
      count += edge_count;
      if (edge_count) {
        ++unique_count;
      }
    }

    auto percent_pct = double(unique_count) / double(gTakenEdgeCount.size());

    LOG(ERROR)
        << "Executed " << count << " branches ("
        << static_cast<int>(percent_pct * 100) << "% condition coverage)";
  }
};

}  // namespace

std::unique_ptr<Tool> CreateFuzzer(void) {
  return std::unique_ptr<Tool>(new FuzzerTool);
}

}  // namespace vmill
