// Copyright (c) 2012 Jakob Progsch, Václav Zeman

#ifndef VMILL_ETC_THREAD_POOL_H_
#define VMILL_ETC_THREAD_POOL_H_

#include <glog/logging.h>

#include <vector>
#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>

class ThreadPool {
 public:
  ThreadPool(size_t);
  template<class F, class ... Args>
  auto Submit(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
  ~ThreadPool();

 private:
  // need to keep track of threads so we can join them
  std::vector<std::thread> workers;
  // the task queue
  std::queue<std::function<void()>> tasks;

  // synchronization
  std::mutex queue_mutex;
  std::condition_variable condition;
  bool stop;
};

// add new work item to the pool
template<class F, class ... Args>
auto ThreadPool::Submit(F&& f, Args&&... args)
    -> std::future<typename std::result_of<F(Args...)>::type> {

  using return_type = typename std::result_of<F(Args...)>::type;

  auto task = std::make_shared<std::packaged_task<return_type()> >(
      std::bind(std::forward<F>(f), std::forward<Args>(args)...));

  std::future<return_type> res = task->get_future();
  do {
    std::unique_lock<std::mutex> lock(queue_mutex);

    // Don't allow enqueueing after stopping the pool.
    CHECK(!stop)
        << "Enqueue happened on stopped ThreadPool.";

    tasks.emplace([task] (void) {(*task)();});
  } while (false);
  condition.notify_one();
  return res;
}

#endif  // VMILL_ETC_THREAD_POOL_H_
