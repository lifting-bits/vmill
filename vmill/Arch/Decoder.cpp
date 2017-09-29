/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <algorithm>
#include <limits>
#include <set>
#include <string>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"

#include "vmill/Arch/Decoder.h"

namespace vmill {
namespace {

// Read instruction bytes using `byte_reader`.
static std::string ReadInstructionBytes(
    const remill::Arch *arch, uint64_t pc, ByteReaderCallback byte_reader) {

  std::string instr_bytes;
  const auto max_num_bytes = arch->MaxInstructionSize();
  instr_bytes.reserve(max_num_bytes);
  for (uint64_t i = 0; i < max_num_bytes; ++i) {
    uint8_t byte = 0;
    if (!byte_reader(pc + i, &byte)) {
      break;
    }
    instr_bytes.push_back(static_cast<char>(byte));
  }
  return instr_bytes;
}

using DecoderWorkList = std::set<uint64_t>;

// Enqueue control flow targets for processing. In some cases we enqueue
// work as being derived from a linear scan rather tha from a recursive
// scan.
static void AddSuccessorsToWorkList(const remill::Instruction &instr,
                                    DecoderWorkList &work_list) {
  switch (instr.category) {
    case remill::Instruction::kCategoryInvalid:
    case remill::Instruction::kCategoryError:
    case remill::Instruction::kCategoryIndirectJump:
    case remill::Instruction::kCategoryIndirectFunctionCall:
    case remill::Instruction::kCategoryFunctionReturn:
    case remill::Instruction::kCategoryAsyncHyperCall:
      break;

    case remill::Instruction::kCategoryNormal:
    case remill::Instruction::kCategoryNoOp:
    case remill::Instruction::kCategoryConditionalAsyncHyperCall:
      work_list.insert(instr.next_pc);
      break;

    case remill::Instruction::kCategoryDirectJump:
    case remill::Instruction::kCategoryDirectFunctionCall:
      work_list.insert(instr.branch_taken_pc);
      break;

    case remill::Instruction::kCategoryConditionalBranch:
      work_list.insert(instr.branch_taken_pc);
      work_list.insert(instr.next_pc);
      break;
  }
}

}  // namespace

// Starting from `start_pc`, read executable bytes out of a memory region
// using `byte_reader`, and returns a mapping of decoded instruction program
// counters to the decoded instructions themselves.
InstructionMap Decode(const remill::Arch *arch, uint64_t start_pc,
                      ByteReaderCallback byte_reader) {

  unsigned num_blocks = 0;

  DecoderWorkList work_list;
  InstructionMap decoded_insts;

  DLOG(INFO)
      << "Recursively decoding machine code, beginning at "
      << std::hex << start_pc;

  work_list.insert(start_pc);

  while (!work_list.empty()) {
    auto entry_it = work_list.begin();
    const auto pc = *entry_it;
    work_list.erase(entry_it);

    if (decoded_insts.count(pc)) {
      continue;
    }

    remill::Instruction inst;
    auto inst_bytes = ReadInstructionBytes(arch, pc, byte_reader);
    auto decode_successful = arch->DecodeInstruction(pc, inst_bytes, inst);
    decoded_insts[pc] = inst;

    if (!decode_successful) {
      LOG(ERROR)
          << "Cannot decode instruction at " << std::hex << pc;
      break;
    }

    AddSuccessorsToWorkList(inst, work_list);
  }

  DLOG(INFO)
      << "Decoded " << decoded_insts.size()
      << " instructions contained inside of "
      << num_blocks << " blocks, starting from "
      << std::hex << start_pc;

  return decoded_insts;
}

}  // namespace vmill
