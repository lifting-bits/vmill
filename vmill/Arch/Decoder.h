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

#ifndef VMILL_ARCH_DECODER_H_
#define VMILL_ARCH_DECODER_H_

#include <functional>
#include <list>
#include <map>

#include "remill/Arch/Instruction.h"
#include "vmill/BC/Trace.h"

namespace vmill {

class AddressSpace;

using InstructionMap = std::map<PC, remill::Instruction>;

struct DecodedTrace {
  PC pc;  // Entry PC of the trace.
  TraceId id;  //
  InstructionMap instructions;
};

class DecodedTraceList : public std::list<DecodedTrace> {};

// Starting from `start_pc`, read executable bytes out of a memory region
// using `byte_reader`, and returns a mapping of decoded instruction program
// counters to the decoded instructions themselves.
DecodedTraceList DecodeTraces(AddressSpace &addr_space, PC start_pc);

}  // namespace vmill

#endif  // VMILL_ARCH_DECODER_H_
