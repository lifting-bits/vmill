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
#include <memory>
#include <string>
#include <vector>
#include <type_traits>
#include <unordered_map>

namespace llvm {

class Module;
class Function;

}  // namespace llvm
namespace vmill {
namespace detail {

template <typename Ret, typename... Args>
inline static Ret ReturnType(Ret (*)(Args...));


template <typename Ret, typename... Args>
inline static Ret ReturnType(Ret (*)(Args..., ...));

// Enables tools to define wrapper functions for functions that are used
// in the runtime / instrumented bitcode.
#define DEF_WRAPPER_IMPL(name, idx, ...) \
  namespace { \
  using name ## _ret_type = decltype(::vmill::detail::ReturnType(name)); \
  } \
  inline namespace ns_ ## idx { \
  struct name ## _wrapper { \
   public: \
    static name ## _ret_type run(__VA_ARGS__); \
    static decltype(name) *name; \
  }; \
  decltype(name) *name ## _wrapper::name = ::name; \
  } \
  name ## _ret_type ns_ ## idx::name ## _wrapper::run(__VA_ARGS__)

#define DEF_WRAPPER_LINE_COUNT2(name, line, count, ...) \
    DEF_WRAPPER_IMPL(name, line ## _ ## count, ##__VA_ARGS__)

#define DEF_WRAPPER_LINE_COUNT(name, line, count, ...) \
    DEF_WRAPPER_LINE_COUNT2(name, line, count, ##__VA_ARGS__)

#define DEF_WRAPPER(name, ...) \
    DEF_WRAPPER_LINE_COUNT(name, __LINE__, __COUNTER__, ##__VA_ARGS__)

}  // namespace detail

class Tool {
 public:
  // Create a new instance of the tool identified by `name_or_path`. Multiple
  // tools can be specified, delimiting them by colons on Unix systems, and
  // semicolons on Windows systems.
  static std::unique_ptr<Tool> Load(std::string name_or_path);

  virtual ~Tool(void);

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol.
  virtual uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved);

  // Tells us that we are about to be able to instrument the module `module`.
  virtual void PrepareModule(llvm::Module *module);

  // Instrument the runtime module.
  virtual bool InstrumentRuntime(llvm::Module *module);

  // Instrument a lifted function/trace.
  virtual bool InstrumentTrace(llvm::Function *func, uint64_t pc);

  // Called just before the beginning of a run.
  virtual void SetUp(void);

  // Called just after the ending of a run.
  virtual void TearDown(void);

 protected:
  Tool(void);

  template <typename Ret, typename... Args>
  inline void ProvideSymbol(const std::string &name, Ret (*ptr)(Args...)) {
    ProvideSymbol(name, reinterpret_cast<uintptr_t>(ptr));
  }

  // Provide a symbol for linking. The symbol will be unconditionally replaced
  // with `pc`.
  //
  // Note: This is only relevant to symbols in the bitcode. For example, if the
  //       runtime calls `malloc`, then you can provide a replacement for it.
  //       This does not apply to the emulated program calling it's own version
  //       of the `malloc` function.
  void ProvideSymbol(const std::string &name, uint64_t pc);

  template <typename Ret, typename... Args>
  inline void OfferSymbol(const std::string &name, Ret (*ptr)(Args...)) {
    OfferSymbol(name, reinterpret_cast<uintptr_t>(ptr));
  }

  // Provide a symbol for linking. If we don't have an address for the symbol
  // then this lets us map it.
  //
  // Note: This is only relevant to symbols in the bitcode. For example, if the
  //       runtime calls `malloc`, then you can provide a replacement for it.
  //       This does not apply to the emulated program calling it's own version
  //       of the `malloc` function.
  void OfferSymbol(const std::string &name, uint64_t pc);

#define ProvideWrappedSymbol(name) \
    do { \
      auto native_addr = reinterpret_cast<uintptr_t>(::name); \
      auto resolved = FindSymbolForLinking(#name, native_addr); \
      name ## _wrapper::name = reinterpret_cast<decltype(name) *>(resolved); \
      ProvideSymbol(#name, name ## _wrapper::run); \
    } while (false)

#define OfferWrappedSymbol(name) \
    do { \
      auto native_addr = reinterpret_cast<uintptr_t>(::name); \
      auto resolved = FindSymbolForLinking(#name, native_addr); \
      name ## _wrapper::name = reinterpret_cast<decltype(name) *>(resolved); \
      OfferSymbol(#name, name ## _wrapper::run); \
    } while (false

 private:
  std::unordered_map<std::string, uint64_t> provided_symbols;
  std::unordered_map<std::string, uint64_t> offered_symbols;
};

class NullTool : public Tool {
 public:
  virtual ~NullTool(void);
};

// Forwards all requests to a subordinate tool.
class ProxyTool : public Tool {
 public:
  explicit ProxyTool(std::unique_ptr<Tool> tool_);

  virtual ~ProxyTool(void);

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol.
  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) override;

  // Tells us that we are about to be able to instrument the module `module`.
  void PrepareModule(llvm::Module *module) override;

  // Instrument the runtime module.
  bool InstrumentRuntime(llvm::Module *module) override;

  // Instrument a lifted function/trace.
  bool InstrumentTrace(llvm::Function *func, uint64_t pc) override;

  // Called just before the beginning of a run.
  void SetUp(void) override;

  // Called just after the ending of a run.
  void TearDown(void) override;

 protected:
  const std::unique_ptr<Tool> tool;

 private:
  ProxyTool(void) = delete;
};

// Like a proxy tool, but lets one compose an arbitrary number of sub-tools.
class CompositorTool : public Tool {
 public:
  CompositorTool(void) = default;

  explicit CompositorTool(std::unique_ptr<Tool> tool);

  virtual ~CompositorTool(void);

  void AddTool(std::unique_ptr<Tool> tool);

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol.
  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) override;

  // Tells us that we are about to be able to instrument the module `module`.
  void PrepareModule(llvm::Module *module) override;

  // Instrument the runtime module.
  bool InstrumentRuntime(llvm::Module *module) override;

  // Instrument a lifted function/trace.
  bool InstrumentTrace(llvm::Function *func, uint64_t pc) override;

  // Called just before the beginning of a run.
  void SetUp(void) override;

  // Called just after the ending of a run.
  void TearDown(void) override;

 private:
  std::vector<std::unique_ptr<Tool>> tools;
};

}  // namespace

#endif  // VMILL_WORKSPACE_TOOL_H_
