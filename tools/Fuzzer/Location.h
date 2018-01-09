/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#ifndef TOOLS_FUZZER_LOCATION_H_
#define TOOLS_FUZZER_LOCATION_H_

#include <cstdint>

namespace vmill {

using Location = uint32_t;

enum LocationType {
  kLocationTypeBranch,
  kLocationTypeValue
};

// Used to manage a persistent location counter across runs.
class PersistentLocation {
 public:
  explicit PersistentLocation(LocationType type);
  ~PersistentLocation(void);

 private:
  PersistentLocation(void) = delete;

  int fd;

 protected:
  Location loc;
};

}  // namespace vmill

#endif  // TOOLS_FUZZER_LOCATION_H_
