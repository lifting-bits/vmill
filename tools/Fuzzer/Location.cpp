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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/Workspace/Workspace.h"

#include "tools/Fuzzer/Location.h"

namespace vmill {
namespace {

static const char *LocationFileName(LocationType type) {
  switch (type) {
    case kLocationTypeBranch:
      return "last_branch_location";
    case kLocationTypeValue:
      return "value_trace_location";
  }
  return "location";
}

static int OpenLocationFile(LocationType type) {
  std::stringstream ss;
  ss << Workspace::ToolDir() << remill::PathSeparator()
     << LocationFileName(type);

  auto loc_file_name = ss.str();
  auto fd = open(loc_file_name.c_str(), O_RDWR | O_CREAT, 0666);
  auto err = errno;
  CHECK(-1 != fd)
      << "Could not open or create " << loc_file_name << ": "
      << strerror(err);

  return fd;
}

static Location GetCurrentLocation(int fd) {
  auto size = remill::FileSize(fd);

  if (size == sizeof(Location)) {
    Location loc = 0;
    CHECK(0 < read(fd, &loc, sizeof(loc)));
    lseek(fd, 0, SEEK_SET);
    return loc;

  } else if (size) {
    LOG(FATAL)
        << "Corrupted last-location file of size " << size << " bytes.";
  }
  return 0;
}

}  // namespace

PersistentLocation::PersistentLocation(LocationType type)
    : fd(OpenLocationFile(type)),
      loc(GetCurrentLocation(fd)) {}

PersistentLocation::~PersistentLocation(void) {
  ftruncate(fd, 0);
  write(fd, &loc, sizeof(loc));
  CHECK(remill::FileSize(fd) == sizeof(loc));
  close(fd);
}

void CoverSwitch(Location edge, const Location *edges_begin,
                 const Location *edges_end) {

}

void CoverBranch(Location edge, Location not_taken_edge) {

}

void CoverCompare1(Location here, int predicate, uint8_t lhs, uint8_t rhs) {

}

void CoverCompare2(Location here, int predicate, uint16_t lhs, uint16_t rhs) {

}

void CoverCompare4(Location here, int predicate, uint32_t lhs, uint32_t rhs) {

}

void CoverCompare8(Location here, int predicate, uint64_t lhs, uint64_t rhs) {

}

}  // namespace vmill
