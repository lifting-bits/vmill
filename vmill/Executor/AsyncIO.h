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

#ifndef VMILL_EXECUTOR_ASYNCIO_H_
#define VMILL_EXECUTOR_ASYNCIO_H_

#include <unordered_map>

#include "vmill/Workspace/Tool.h"

namespace vmill {

class AsyncIOTool : public ProxyTool {
 public:
  explicit AsyncIOTool(std::unique_ptr<Tool> tool_);

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol.
  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) final;

 private:
  // Variants of functions that will spawn work in the worker pool.
  std::unordered_map<std::string, uint64_t> async_funcs;
};

}  // namespace vmill

#endif  // VMILL_EXECUTOR_ASYNCIO_H_
