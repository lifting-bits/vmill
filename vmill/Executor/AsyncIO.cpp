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

#include "vmill/Executor/AsyncIO.h"
#include "vmill/Executor/Coroutine.h"
#include "vmill/Runtime/Task.h"
#include "vmill/Util/Compiler.h"

#include "third_party/ThreadPool/ThreadPool.h"

DEFINE_uint64(num_io_threads, 0, "Number of I/O threads.");

#ifdef __APPLE__
# define TO_STR_(x) #x
# define TO_STR(x) TO_STR_(x)
# define SYM(a) TO_STR(_ ## a)
#else
# define SYM(a) #a
#endif

namespace vmill {

extern thread_local Task *gTask;

namespace {

// Thread pool that processes blocking system calls.
static std::unique_ptr<ThreadPool> gIOPool;

// Returns the thread pool, and potentially lazily initializes it.
static const std::unique_ptr<ThreadPool> &GetIOThreadPool(void) {
  if (unlikely(!gIOPool)) {
    gIOPool.reset(new ThreadPool(FLAGS_num_io_threads));
  }
  return gIOPool;
}

// Wraps around a blocking system call (passed as the first argument to get
// all of the type information), whose implementation is at `target` (this
// second argument is so that an instrumentation tool can substitute its own
// implementation (via `Tool::FindSymbolForLinking`).
//
// Because the types of system calls may not be unique, an extra `Tag` parameter
// is passed to the template, and there should be a unique tag type per system
// call to be wrapped.
template <typename Tag, typename Ret, typename... Args>
static uint64_t AsyncWrapper_(Ret (*)(Args...), uintptr_t target) {
  using FuncType = Ret(Args...);

  static FuncType *func_to_run;
  func_to_run = reinterpret_cast<FuncType *>(target);

  struct Wrapper {

    struct OutVal {
      Ret ret_val;
      int new_errno;
    };

    // Calls `func_to_run` in the context of the worker thread.
    static OutVal run_func_async(Task *task, Args... args) {

      // Note: This is thread-local. Other instrumentation tools may want
      //       access to the task, e.g. if they are going to generate fuzzed
      //       info for `read` syscalls on demand.
      gTask = task;
      errno = 0;
      auto ret = func_to_run(args...);
      auto new_errno = errno;
      gTask = nullptr;

      return {ret, new_errno};
    }

    // Enqueue our blocking function to be run on a separate thread. Then
    // wait for a result. If the syscall is still running, then yield the
    // coroutine's execution to process other tasks, otherwise continue on
    // with the value.
    static Ret run_func(Args... args) {
      auto coro = gTask->async_routine;
      auto &pool = GetIOThreadPool();
      std::future<OutVal> future = pool->Submit(run_func_async, gTask, args...);
      auto done = false;
      do {
        switch (future.wait_for(std::chrono::nanoseconds(100))) {
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
      return res.ret_val;
    }
  };

  return reinterpret_cast<uintptr_t>(Wrapper::run_func);
}

#define AsyncWrapper(func_name) \
  AsyncWrapper_<struct async_ ## func_name>( \
    func_name, \
    this->ProxyTool::FindSymbolForLinking( \
        SYM(func_name), reinterpret_cast<uintptr_t>(func_name)))

}  // namespace

AsyncIOTool::AsyncIOTool(std::unique_ptr<Tool> tool_)
    : ProxyTool(std::move(tool_)) {

  async_funcs[SYM(read)] = AsyncWrapper(read);
  async_funcs[SYM(write)] = AsyncWrapper(write);
  async_funcs[SYM(connect)] = AsyncWrapper(connect);
  async_funcs[SYM(recvfrom)] = AsyncWrapper(recvfrom);
  async_funcs[SYM(sendto)] = AsyncWrapper(sendto);
  async_funcs[SYM(sendmsg)] = AsyncWrapper(sendmsg);
  async_funcs[SYM(recvmsg)] = AsyncWrapper(recvmsg);
  async_funcs[SYM(poll)] = AsyncWrapper(poll);
  async_funcs[SYM(select)] = AsyncWrapper(select);
  async_funcs[SYM(getaddrinfo)] = AsyncWrapper(getaddrinfo);
  async_funcs[SYM(getnameinfo)] = AsyncWrapper(getnameinfo);
  async_funcs[SYM(sleep)] = AsyncWrapper(sleep);
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
