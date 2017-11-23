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

#include <algorithm>
#include <limits>
#include <set>
#include <string>
#include <utility>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"

#include "vmill/Arch/Decoder.h"
#include "vmill/Program/AddressSpace.h"
#include "vmill/Util/Hash.h"

namespace vmill {
namespace {

// Read instruction bytes using `byte_reader`.
static std::string ReadInstructionBytes(
    const remill::Arch *arch, AddressSpace &addr_space, uint64_t pc) {

  std::string instr_bytes;
  const auto max_num_bytes = arch->MaxInstructionSize();
  instr_bytes.reserve(max_num_bytes);
  for (uint64_t i = 0; i < max_num_bytes; ++i) {
    uint8_t byte = 0;
    auto byte_pc = pc + i;
    if (!addr_space.TryReadExecutable(static_cast<PC>(byte_pc), &byte)) {
      LOG(WARNING)
          << "Stopping decode at non-executable byte "
          << std::hex << byte_pc << std::dec;
      break;
    }
    instr_bytes.push_back(static_cast<char>(byte));
  }
  return instr_bytes;
}

using DecoderWorkList = std::set<uint64_t>;

// Enqueue control flow targets for processing. We only follow directly
// reachable control-flow targets in this list.
static void AddSuccessorsToWorkList(const remill::Instruction &inst,
                                    DecoderWorkList &work_list) {
  switch (inst.category) {
    case remill::Instruction::kCategoryInvalid:
    case remill::Instruction::kCategoryError:
    case remill::Instruction::kCategoryIndirectJump:
    case remill::Instruction::kCategoryIndirectFunctionCall:
    case remill::Instruction::kCategoryFunctionReturn:
    case remill::Instruction::kCategoryAsyncHyperCall:
      break;

    case remill::Instruction::kCategoryDirectFunctionCall:
      // NOTE(pag): These targets are added to the successor trace list, and
      //            direct function calls are lifted using the
      //            `__remill_function_call` intrinsic.
      break;

    case remill::Instruction::kCategoryNormal:
    case remill::Instruction::kCategoryNoOp:
    case remill::Instruction::kCategoryConditionalAsyncHyperCall:
      work_list.insert(inst.next_pc);
      break;

    case remill::Instruction::kCategoryDirectJump:
      work_list.insert(inst.branch_taken_pc);
      break;

    case remill::Instruction::kCategoryConditionalBranch:
      work_list.insert(inst.branch_taken_pc);
      work_list.insert(inst.next_pc);
      break;
  }
}

static uint64_t GetLoadedEffectiveAddress(const remill::Instruction &inst) {
  for (const auto &op : inst.operands) {
    // PC-relative address.
    if (op.type == remill::Operand::kTypeAddress &&
        op.addr.base_reg.name == "PC" &&
        op.addr.index_reg.name.empty() &&
        op.addr.displacement) {
      return static_cast<uint64_t>(
          static_cast<int64_t>(inst.pc) + op.addr.displacement);

    // Absolute address.
    } else if (op.type == remill::Operand::kTypeAddress &&
               op.addr.base_reg.name.empty() &&
               op.addr.index_reg.name.empty() &&
               op.addr.displacement) {
      return static_cast<uint64_t>(op.addr.displacement);
    }
  }
  return 0;
}

// Enqueue control flow targets that will potentially represent future traces.
static void AddSuccessorsToTraceList(const remill::Arch *arch,
                                     AddressSpace &addr_space,
                                     const remill::Instruction &inst,
                                     DecoderWorkList &work_list) {

  switch (inst.category) {
//    case remill::Instruction::kCategoryIndirectFunctionCall:
//    case remill::Instruction::kCategoryDirectFunctionCall:
//      if (addr_space.CanExecute(inst.next_pc)) {
//        work_list.insert(inst.next_pc);
//      }
//      break;

    case remill::Instruction::kCategoryDirectFunctionCall:
      work_list.insert(inst.branch_taken_pc);
      break;

    // Thunks, e.g. `jmp [0xf00]`.
    case remill::Instruction::kCategoryIndirectJump: {
      auto thunk = GetLoadedEffectiveAddress(inst);
      if (!thunk) {
        return;
      }

      alignas(uint64_t) uint8_t bytes[8] = {};
      auto addr_size_bytes = arch->address_size / 8;
      for (uint64_t i = 0; i < addr_size_bytes; ++i) {
        if (!addr_space.TryRead(thunk + i, &(bytes[i]))) {
          return;
        }
      }

      // TODO(pag): Assumes little endian.
      uint64_t addr = reinterpret_cast<uint64_t &>(bytes[0]);
      if (addr_space.CanRead(addr) && addr_space.CanExecute(addr)) {
        DLOG(INFO)
            << "Indirect jump at " << std::hex << inst.pc
            << " looks like a thunk that invokes " << addr << std::dec;
        work_list.insert(addr);
      }
      break;
    }
    default:
      break;
  }
}

// The 'version' of this trace is a hash of the instruction bytes.
static TraceId HashTraceInstructions(const DecodedTrace &trace) {
  const auto &insts = trace.instructions;

  Hasher<uint32_t> hash1(static_cast<uint32_t>(0xdeadbeef));
  Hasher<uint32_t> hash2(static_cast<uint32_t>(insts.size()));

  for (const auto &entry : insts) {
    hash1.Update(entry.second.bytes.data(), entry.second.bytes.size());
    hash2.Update(entry.second.bytes.data(), entry.second.bytes.size());
  }

  return {static_cast<TraceHash>(hash1.Digest()),
          static_cast<TraceHash>(hash2.Digest())};
}

}  // namespace

// Starting from `start_pc`, read executable bytes out of a memory region
// using `byte_reader`, and returns a mapping of decoded instruction program
// counters to the decoded instructions themselves.
DecodedTraceList DecodeTraces(AddressSpace &addr_space, PC start_pc) {

  DecodedTraceList traces;

  auto arch = remill::GetTargetArch();
  auto code_version = addr_space.ComputeCodeVersion();

  DecoderWorkList trace_list;
  DecoderWorkList work_list;

  DLOG(INFO)
      << "Recursively decoding machine code, beginning at "
      << std::hex << static_cast<uint64_t>(start_pc);

  trace_list.insert(static_cast<uint64_t>(start_pc));

  while (!trace_list.empty()) {
    auto trace_it = trace_list.begin();
    const auto trace_pc = *trace_it;
    trace_list.erase(trace_it);

    if (addr_space.IsMarkedTraceHead(static_cast<PC>(trace_pc))) {
      continue;
    }

    addr_space.MarkAsTraceHead(static_cast<PC>(trace_pc));
    work_list.insert(trace_pc);

    DecodedTrace trace;
    trace.pc = static_cast<PC>(trace_pc);
    trace.code_version = code_version;

    while (!work_list.empty()) {
      auto entry_it = work_list.begin();
      const auto pc = *entry_it;
      work_list.erase(entry_it);

      if (trace.instructions.count(static_cast<PC>(pc))) {
        continue;
      }

      remill::Instruction inst;
      auto inst_bytes = ReadInstructionBytes(arch, addr_space, pc);
      auto decode_successful = arch->DecodeInstruction(pc, inst_bytes, inst);
      trace.instructions[static_cast<PC>(pc)] = inst;

      if (!decode_successful) {
        LOG(WARNING)
            << "Cannot decode instruction at " << std::hex << pc << std::dec
            << ": " << inst.Serialize();
        break;
      } else {
        AddSuccessorsToWorkList(inst, work_list);
        AddSuccessorsToTraceList(arch, addr_space, inst, trace_list);
      }
    }

    trace.id = HashTraceInstructions(trace);

    DLOG(INFO)
        << "Decoded " << trace.instructions.size()
        << " instructions starting from "
        << std::hex << static_cast<uint64_t>(trace.pc) << std::dec;

    traces.push_back(std::move(trace));
  }

  return traces;
}

}  // namespace vmill
