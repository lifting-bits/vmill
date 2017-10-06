/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef VMILL_ARCH_DECODER_H_
#define VMILL_ARCH_DECODER_H_

#include <functional>
#include <list>
#include <map>

#include "remill/Arch/Instruction.h"

namespace vmill {

class AddressSpace;

using InstructionMap = std::map<uint64_t, remill::Instruction>;

struct DecodedTrace {
  uint64_t entry_pc;
  uint64_t hash;
  InstructionMap instructions;
};

// Starting from `start_pc`, read executable bytes out of a memory region
// using `byte_reader`, and returns a mapping of decoded instruction program
// counters to the decoded instructions themselves.
std::list<DecodedTrace> DecodeTraces(AddressSpace &addr_space,
                                     uint64_t start_pc);

}  // namespace vmill

#endif  // VMILL_ARCH_DECODER_H_
