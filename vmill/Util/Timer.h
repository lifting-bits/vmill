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

#ifndef VMILL_UTIL_TIMER_H_
#define VMILL_UTIL_TIMER_H_

#include <ctime>

namespace vmill {

class Timer {
 public:
  Timer(void);

  // Returns the number of elapsed seconds since the instantiation of the
  // time.
  double ElapsedSeconds(void) const;

 public:
  clock_t begin;
};

}  // namespace vmill

#endif  // VMILL_UTIL_TIMER_H_
