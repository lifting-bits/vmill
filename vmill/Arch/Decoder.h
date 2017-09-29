/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef VMILL_ARCH_DECODER_H_
#define VMILL_ARCH_DECODER_H_

#include <functional>
#include <map>

#include "remill/Arch/Instruction.h"
#include "vmill/Util/Callback.h"

namespace remill {
class Arch;
}  // namespace remill
namespace vmill {

using InstructionMap = std::map<uint64_t, remill::Instruction>;

// Starting from `start_pc`, read executable bytes out of a memory region
// using `byte_reader`, and returns a mapping of decoded instruction program
// counters to the decoded instructions themselves.
InstructionMap Decode(const remill::Arch *arch, uint64_t start_pc,
                      ByteReaderCallback byte_reader);

}  // namespace vmill

#endif  // VMILL_ARCH_DECODER_H_
