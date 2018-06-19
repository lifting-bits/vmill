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

#ifndef VMILL_EXECUTOR_CODECACHE_H_
#define VMILL_EXECUTOR_CODECACHE_H_

#include <memory>
#include <unordered_map>

#include "vmill/BC/Trace.h"

struct ArchState;
struct Memory;

namespace llvm {
class LLVMContext;
class Module;
}  // namespace llvm
namespace vmill {

class AddressSpace;
class Tool;
using LiftedFunction = Memory *(ArchState *, PC, Memory *);

// Manages the native and lifted code caches.
class CodeCache {
 public:
  virtual ~CodeCache(void);

  static std::unique_ptr<CodeCache> Create(
      std::unique_ptr<Tool> tool_,
      const std::shared_ptr<llvm::LLVMContext> &context_);

  virtual void AddModuleToCache(
      const std::unique_ptr<llvm::Module> &module) = 0;

  virtual LiftedFunction *Lookup(TraceId trace_id) const = 0;

  virtual uintptr_t Lookup(const char *symbol) = 0;

  // Called to run constructors in the runtime.
  virtual void RunConstructors(void) = 0;

  // Called just before the beginning of a run.
  virtual void SetUp(void) = 0;

  // Called just after the end of a run.
  virtual void TearDown(void) = 0;

 protected:
  CodeCache(void);
};

}  // namespace vmill

#endif  // VMILL_EXECUTOR_CODECACHE_H_
