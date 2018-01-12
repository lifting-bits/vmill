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
#include <unistd.h>
#include <fcntl.h>

#include "tools/Fuzzer/Fuzzer.h"
#include "tools/Fuzzer/Location.h"

#include "vmill/Util/Compiler.h"

DEFINE_string(path_to_fuzz, "/dev/stdin", "The path to the file to fuzz");

namespace vmill {
namespace {

static std::vector<uint64_t> gTakenEdgeCount;
static std::vector<uint64_t> gNotTakenEdgeCount;
static int gFdToFuzz = -1;

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

DEF_WRAPPER(read, int fd, void *data, size_t size) {
  if (0 <= fd && gFdToFuzz == fd) {
    LOG(ERROR) << "read!!!";
    return 0;
  } else {
    return read(fd, data, size);
  }
}

DEF_WRAPPER(open, const char *path, int oflag, mode_t mode) {
  auto fd = open(path, oflag, mode);
  if (FLAGS_path_to_fuzz == path) {
    gFdToFuzz = fd;
  }
  return fd;
}

class FuzzerTool : public Tool {
 public:
  FuzzerTool(void) {
    ProvideSymbol("__cov_cmp_1", CoverCompare1);
    ProvideSymbol("__cov_cmp_2", CoverCompare2);
    ProvideSymbol("__cov_cmp_4", CoverCompare4);
    ProvideSymbol("__cov_cmp_8", CoverCompare8);
    ProvideSymbol("__cov_switch", CoverSwitch);
    ProvideSymbol("__cov_branch", CoverBranch);

    ProvideWrappedSymbol(read);
    ProvideWrappedSymbol(open);
  }

  virtual ~FuzzerTool(void) {}

  void SetUp(void) final {
    gTakenEdgeCount.clear();
    gNotTakenEdgeCount.clear();
    gFdToFuzz = -1;
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
