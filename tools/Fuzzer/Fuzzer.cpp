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

#include "tools/Fuzzer/Fuzzer.h"
#include "tools/Fuzzer/Location.h"

namespace vmill {
namespace {

static void CoverSwitch(Location edge, const Location *edges_begin,
                        const Location *edges_end) {

}

static void CoverBranch(Location edge, Location not_taken_edge) {

}

static void CoverCompare1(Location here, int, uint8_t lhs, uint8_t rhs) {

}

static void CoverCompare2(Location here, int, uint16_t lhs, uint16_t rhs) {

}

static void CoverCompare4(Location here, int, uint32_t lhs, uint32_t rhs) {

}

static void CoverCompare8(Location here, int, uint64_t lhs, uint64_t rhs) {

}

class CoverageGuidedFuzzerTool : public Tool {
 public:
  virtual ~CoverageGuidedFuzzerTool(void) {}

  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) override {

    if (name == "__cov_cmp_1") {
      return reinterpret_cast<uintptr_t>(CoverCompare1);
    } else if (name == "__cov_cmp_2") {
      return reinterpret_cast<uintptr_t>(CoverCompare2);
    } else if (name == "__cov_cmp_4") {
      return reinterpret_cast<uintptr_t>(CoverCompare4);
    } else if (name == "__cov_cmp_8") {
      return reinterpret_cast<uintptr_t>(CoverCompare8);
    } else if (name == "__cov_switch") {
      return reinterpret_cast<uintptr_t>(CoverSwitch);
    } else if (name == "__cov_branch") {
      return reinterpret_cast<uintptr_t>(CoverBranch);
    } else {
      return resolved;
    }
  }

  void SetUp(void) final {

  }

  void TearDown(void) final {

  }
};

}  // namespace

std::unique_ptr<Tool> CreateFuzzer(void) {
  return std::unique_ptr<Tool>(new CoverageGuidedFuzzerTool);
}

}  // namespace vmill
