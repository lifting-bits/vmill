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

#include <glog/logging.h>

#include <fstream>

#include "remill/OS/FileSystem.h"

#include "vmill/Program/Snapshot.h"

namespace vmill {

// Load a snapshot from a file.
ProgramSnapshotPtr LoadSnapshotFromFile(const std::string &snapshot_path) {
  CHECK(remill::FileExists(snapshot_path))
      << "Snapshot file " << snapshot_path << " does not exist. Make sure "
      << "to create it with vmill-snapshot";

  std::ifstream fs(snapshot_path, std::ios::binary);
  CHECK(fs)
      << "Snapshot file " << snapshot_path
      << " could not be opened for reading";

  ProgramSnapshotPtr snap(new snapshot::Program);
  CHECK(snap->ParseFromIstream(&fs))
      << "Unable parse snapshot file " << snapshot_path;

  LOG(INFO)
      << "Parsed snapshot file " << snapshot_path;

  return snap;
}

}  // namespace vmill
