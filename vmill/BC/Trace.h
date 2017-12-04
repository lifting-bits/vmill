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

#ifndef VMILL_BC_TRACE_H_
#define VMILL_BC_TRACE_H_

#include <cstdint>

#include "vmill/Util/Hash.h"

namespace llvm {
class Module;
}  // namespace llvm
namespace vmill {

using TraceHashBaseType = uint64_t;
enum class TraceHash : TraceHashBaseType;
enum class PC : uint64_t;
enum class CodeVersion : uint64_t;

// Hash of the bytes of the machine code in the trace.
struct TraceId {
 public:
  TraceHash hash1;
  TraceHash hash2;

  inline bool operator==(const TraceId &that) const {
    return hash1 == that.hash1 && hash2 == that.hash2;
  }
} __attribute__((packed));

struct LiveTraceId {
 public:
  PC pc;  // Entry PC of the trace.
  CodeVersion code_version;  // Hash of all executable memory.

  inline bool operator==(const LiveTraceId &that) const {
    return pc == that.pc && code_version == that.code_version;
  }
};

}  // namespace vmill

VMILL_MAKE_STD_HASH_OVERRIDE(vmill::TraceId);
VMILL_MAKE_STD_HASH_OVERRIDE(vmill::LiveTraceId);

#endif  // VMILL_BC_TRACE_H_
