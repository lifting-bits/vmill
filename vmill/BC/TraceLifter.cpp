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
#include "remill/Arch/Name.h"

#include "remill/BC/ABI.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/BC/Optimizer.h"
#include "remill/OS/OS.h"

#include "vmill/Program/AddressSpace.h"
#include "vmill/Util/Hash.h"

DECLARE_bool(verbose);

namespace vmill {
namespace {
class VmillTraceManager: public remill::TraceManager{
  public:
    virtual ~VmillTraceManager(void) = default;
    explicit TraceManager(AddressSpace &addr_space);
    virtual void ForEachDevirtualizedTarget(
        const Instruction &inst, 
        std::function<void(uint64_t addr, uint8_t *byte)> func);

    virtual bool TryReadExecutableByte(uint64_t addr, uint8_t *byte);

  protected:
    virtual void SetLiftedTraceDefinition(
        uint64_t addr, llvm::Function *lifted_func);

    llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) override;

    llvm::Function *GetLiftedTraceDefinition(uint64_t addr) override;
    
  public:
    AddressSpace &memory;
    std::unordered_map<uint64_t, llvm::Function *> traces;
};

void VmillTraceManager::ForEachDevirtualizeTarget(
    const Instruction &inst,
    std::function<void(uint64_t, DevirtualizedTargetKind)> func){
  return 
}

VmillTraceManager::VmillTraceManager(AddressSpace &addr_space)
    : memory(addr_space) {}
 
VmillTraceManager::~TraceManager(void) {}

bool VmillTraceManager::TryReadExecutableByte(uint64_t addr, uint8_t *byte){
  return memory.TryReadexecutable(static_cast<PC>(byte_pc), byte);
}

void VmillTraceManager::SetLiftedTraceDefinition(
        uint64_t addr, llvm::Function *lifted_func){
  traces[addr] = lifted_func;
}

llvm::Function *GetLiftedTraceDeclaration(uint64_t addr){
  auto trace_it = trace.find(addr);
  if (trace_it != traces.end()){
    return trace_it -> second;
  } else {
    return nullptr;
  }
}

llvm::Function *GetLiftedTraceDefinition(uint64_t addr){
  return GetLiftedTraceDeclaration(addr);
}

class VmillTraceLifter: public remill::TraceLifter {
    //The goal here is to get the Lift function working
    public:
      inline VmillTraceLifter(remill::InstructionLifter &inst_lifter_,
                              VmillTraceManager &manager_)
          : remill::TraceLifter(&inst_lifter_, &manager_) {}

      VmillTraceLifter(remill::InstructionLifter *inst_lifter_,
                      VmillTraceManager *manager_);

      std::unique_ptr<llvm::Module> VmillLift(uint64_t addr_);
};

VmillTraceLifter::VmillTraceLifter(remill::InstructionLifter *inst_lifter_,
                 VmillTraceManager *manager_)
    : remill::TraceLifter(inst_lifter_, manager_) {}

}

std::unique_ptr<llvm::Module> VmillTraceLifter::VmillLift(uint64_t addr_) {
  bool lift = remill::TraceLifter::Lift(addr_);
  //figure out how to access base manager and base instruction lifter
  //finish optimization stuff done in the lifter to return back a module
  //line up functionality in Lifter.cpp in vmill 
  //re-write executor to accept this API
  //write foreach
  //patch remill
  //add binja support
  //pag rewrites address space
  //add klee support
  //finally rewrite scheduling stuff in cyberdyne
  //re write scheduler for rodeo day API
  //test on Rodeo-Day
  //Chill Bill
}

} //namespace vmill
