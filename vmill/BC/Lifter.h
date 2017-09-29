/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef VMILL_BC_LIFTER_H_
#define VMILL_BC_LIFTER_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "vmill/Util/Callback.h"

namespace llvm {
class LLVMContext;
class Module;
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill
namespace vmill {

// A single-entry, multiple-exit trace, starting at `pc`.
struct LiftedFunction {
  const uint64_t pc;
  const uint64_t hash;
  llvm::Function * const func;
};

// Lifts machine code instructions into LLVM functions.
class Lifter {
 public:
  virtual ~Lifter(void);

  static Lifter *Create(
      const std::shared_ptr<llvm::LLVMContext> &context);

  // Lift the code starting at `pc` into the module `module`.
  //
  // Note: Lifting is always successful. Even invalid instructions are 'lifted',
  //       but lifted into bitcode functions that will dispatch to Remill's
  //       error intrinsics.
  virtual LiftedFunction LiftIntoModule(
      uint64_t pc, const ByteReaderCallback &cb,
      const std::unique_ptr<llvm::Module> &module) = 0;

 protected:
  Lifter(void);
};

}  // namespace vmill

#endif  // VMILL_BC_LIFTER_H_
