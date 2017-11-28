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
#ifndef VMILL_WORKSPACE_TOOL_H_
#define VMILL_WORKSPACE_TOOL_H_

#include <cstdint>
#include <string>
#include <memory>

namespace vmill {

class Tool {
 public:
  // Create a new instance of the tool identified by `name_or_path`.
  static std::unique_ptr<Tool> Load(const std::string &name_or_path);

  virtual ~Tool(void);

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol.
  virtual uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved);

 protected:
  Tool(void);
};

class NullTool : public Tool {
 public:
  virtual ~NullTool(void);
};

class ProxyTool : public Tool {
 public:
  explicit ProxyTool(std::unique_ptr<Tool> tool_);

  virtual ~ProxyTool(void);

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol.
  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) override;

 protected:
  const std::unique_ptr<Tool> tool;

 private:
  ProxyTool(void) = delete;
};

}  // namespace

#endif  // VMILL_WORKSPACE_TOOL_H_
