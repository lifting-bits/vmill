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
  // Entry PC of the trace.
  PC pc;

  // Hash of all instruction bytes of the trace.
  TraceHash hash;

  inline bool operator==(const TraceId &that) const {
    return pc == that.pc && hash == that.hash;
  }
} __attribute__((packed));

struct LiveTraceId {
 public:
  // Entry PC of the trace.
  PC pc;

  // Hash of all bytes of memory in the `MappedRange` containing this `pc`.
  CodeVersion code_version;

  inline bool operator==(const LiveTraceId &that) const {
    return pc == that.pc && code_version == that.code_version;
  }
};

}  // namespace vmill

namespace std {

template <>
struct hash<vmill::TraceId> {
 public:
  using result_type = uint64_t;
  using argument_type = vmill::TraceId;
  inline result_type operator()(const argument_type &val) const {
    return static_cast<result_type>(val.hash);
  }
};

template <>
struct hash<vmill::LiveTraceId> {
 public:
  using result_type = uint64_t;
  using argument_type = vmill::LiveTraceId;
  inline result_type operator()(const argument_type &val) const {
    const auto pc_uint = static_cast<uint64_t>(val.pc);
    const auto code_version_uint = static_cast<uint64_t>(val.code_version);
    return pc_uint ^ code_version_uint;
  }
};

}  // namespace std

#endif  // VMILL_BC_TRACE_H_
