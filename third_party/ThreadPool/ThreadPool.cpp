// Copyright (c) 2012 Jakob Progsch, Václav Zeman

#include "third_party/ThreadPool/ThreadPool.h"

// the constructor just launches some amount of workers
ThreadPool::ThreadPool(size_t threads)
    : stop(false) {
  for (size_t i = 0; i < threads; ++i)
    workers.emplace_back(
        [this] (void) {
          for(;;) {
            std::function<void()> task;

            do {
              std::unique_lock<std::mutex> lock(this->queue_mutex);
              this->condition.wait(
                  lock,
                  [this] (void) {
                    return this->stop || !this->tasks.empty();
                  });

              if (this->stop && this->tasks.empty()) {
                return;
              }
              task = std::move(this->tasks.front());
              this->tasks.pop();
            } while (false);

            task();
          }
        });
}

// the destructor joins all threads
ThreadPool::~ThreadPool() {
  do {
    std::unique_lock<std::mutex> lock(queue_mutex);
    stop = true;
  } while (false);
  condition.notify_all();
  for (std::thread &worker : workers) {
    worker.join();
  }
}
