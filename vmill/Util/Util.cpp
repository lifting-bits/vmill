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

#include <glog/logging.h>

#include "vmill/Util/Util.h"

namespace vmill {

std::vector<std::string> SplitPathList(std::string path_list, char sep) {
  std::vector<std::string> parts;
  if (path_list.empty()) {
    return parts;
  }

  if (!sep) {
    parts.push_back(path_list);
    return parts;
  }

  for (auto pos = path_list.find(sep);
       pos != std::string::npos;
       pos = path_list.find(sep)) {

    auto part = path_list.substr(0, pos);
    path_list.erase(0, pos + 1);

    if (!part.empty()) {
      parts.push_back(part);
    }
  }

  if (!path_list.empty()) {
    parts.push_back(path_list);
  }

  return parts;
}

}  // namespace vmill
