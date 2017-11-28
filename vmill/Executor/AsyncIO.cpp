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

#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unordered_map>

#include "vmill/Etc/ThreadPool/ThreadPool.h"
#include "vmill/Executor/AsyncIO.h"
#include "vmill/Executor/Coroutine.h"
#include "vmill/Util/Compiler.h"

DEFINE_uint64(num_io_threads, 0, "Number of I/O threads.");

namespace vmill {

extern thread_local Task *gTask;

namespace {

static std::unique_ptr<ThreadPool> gPool;

static std::unordered_map<std::string, uintptr_t> gIOFunctions;

// Returns the thread pool, and potentially lazily initializes it.
static const std::unique_ptr<ThreadPool> &GetThreadPool(void) {
  if (unlikely(!gPool)) {
    gPool.reset(new ThreadPool(FLAGS_num_io_threads));
  }
  return gPool;
}

template <typename Tag, typename Ret, typename... Args>
static uint64_t AsyncWrapper_(Ret (*)(Args...), uintptr_t target) {
  using FuncType = Ret(Args...);

  static FuncType *func_to_run;
  func_to_run = reinterpret_cast<FuncType *>(target);

  struct Wrapper {
    struct OutVal {
      Ret ret;
      int new_errno;
    };

    static OutVal run_func_async(Args... args) {
      errno = 0;
      auto ret = func_to_run(args...);
      auto new_errno = errno;
      return {ret, new_errno};
    }

    static Ret run_func(Args... args) {
      auto coro = gTask->async_routine;
      auto &pool = GetThreadPool();
      std::future<OutVal> future = pool->Submit(run_func_async, args...);
      auto done = false;
      do {
        switch (future.wait_for(std::chrono::nanoseconds(300))) {
          case std::future_status::deferred:
            future.wait();
            done = true;
            break;
          case std::future_status::ready:
            done = true;
            break;
          case std::future_status::timeout:
            coro->Pause(gTask);
            break;
        }
      } while (!done);

      auto res = future.get();
      errno = res.new_errno;
      return res.ret;
    }
  };

  return reinterpret_cast<uintptr_t>(Wrapper::run_func);
}

#define AsyncWrapper(func_name) \
  AsyncWrapper_<struct async_ ## func_name>( \
    func_name, this->ProxyTool::FindSymbolForLinking(\
                   #func_name, reinterpret_cast<uintptr_t>(func_name)))

}  // namespace

AsyncIOTool::AsyncIOTool(std::unique_ptr<Tool> tool_)
    : ProxyTool(std::move(tool_)) {

  async_funcs["read"] = AsyncWrapper(read);
  async_funcs["write"] = AsyncWrapper(write);
  async_funcs["poll"] = AsyncWrapper(poll);
  async_funcs["select"] = AsyncWrapper(select);
  async_funcs["getaddrinfo"] = AsyncWrapper(getaddrinfo);
  async_funcs["getnameinfo"] = AsyncWrapper(getnameinfo);
  async_funcs["sleep"] = AsyncWrapper(sleep);
}

// Called when lifted bitcode or the runtime needs to resolve an external
// symbol.
uint64_t AsyncIOTool::FindSymbolForLinking(
    const std::string &name, uint64_t resolved) {
  auto it = async_funcs.find(name);
  if (it != async_funcs.end()) {
    return it->second;
  } else {
    return this->ProxyTool::FindSymbolForLinking(name, resolved);
  }
}

}  // namespace
