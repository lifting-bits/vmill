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

#include <algorithm>
#include <cinttypes>
#include <climits>
#include <csignal>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/Program/Snapshot.h"
#include "vmill/Workspace/Workspace.h"

DEFINE_uint64(breakpoint, 0, "Address of where to inject a breakpoint.");
DECLARE_string(arch);
DECLARE_string(os);

namespace vmill {

// Copy the register state from the tracee with PID `pid` into the file
// with FD `fd`.
extern void CopyX86TraceeState(pid_t pid, pid_t tid, int64_t memory_id,
                               snapshot::Program *snapshot);

extern void CopyAArch64TraceeState(pid_t pid, pid_t tid, int64_t memory_id,
                                   snapshot::Program *snapshot);

}  // namespace vmill

namespace {

enum : int {
  kMaxNumAttempts = 10
};

static int gTraceeArgc = 0;

static char **gTraceeArgv = nullptr;

static vmill::snapshot::Program gSnapshot;

// Extract out the arguments of the tracee from the arguments to the tracer.
bool ExtractTraceeArgs(int *argc, char **argv) {
  const auto old_argc = *argc;
  auto new_argc = 0;

  for (auto i = 0; i < old_argc; ++i) {
    auto arg = argv[i];
    if (!strcmp("--", arg)) {
      break;
    } else {
      ++new_argc;
    }
  }

  if (old_argc == new_argc) {
    return false;
  }

  *argc = new_argc;
  argv[new_argc] = nullptr;
  gTraceeArgv = &(argv[new_argc + 1]);
  gTraceeArgc = old_argc - new_argc - 1;

  // Copy the tracee arguments into the snapshot.
  for (auto i = 0; i < gTraceeArgc; ++i) {
    gSnapshot.add_argv(gTraceeArgv[i]);
  }

  return true;
}

// Print out an argument, with double quotes in the argument escaped.
static void EscapeQuotedArg(std::stringstream &ss, const char *arg) {
  while (auto chr = *(arg++)) {
    if ('"' == chr) {
      ss << '\\';
    }
    ss << chr;
  }
}

// Log the command for the tracee.
static void LogPrepareExec(void) {
  std::stringstream ss;
  for (auto i = 0; i < gTraceeArgc; ++i) {
    if (strchr(gTraceeArgv[i], ' ')) {
      ss << '"';
      EscapeQuotedArg(ss, gTraceeArgv[i]);
      ss << '"' << ' ';
    } else {
      ss << gTraceeArgv[i] << " ";
    }
  }
  LOG(INFO)
      << "Preparing to execute tracee: " << ss.str();
}

// Returns `true` if a signal looks like an error signal. Used when checking
// `WIFSTOPPED`.
static bool IsErrorSignal(int sig) {
  switch (sig) {
    case SIGHUP:
    case SIGQUIT:
    case SIGABRT:
    case SIGBUS:
    case SIGFPE:
    case SIGKILL:
    case SIGSEGV:
    case SIGPIPE:
    case SIGTERM:
      return true;
    default:
      return false;
  }
}

// Enable tracing of the target binary.
static void EnableTracing(void) {
  for (auto i = 0UL; i < kMaxNumAttempts; i++) {
    if (!ptrace(PTRACE_TRACEME, 0, nullptr, nullptr)) {
      raise(SIGSTOP);
      return;
    }
  }
  LOG(FATAL)
      << "Failed to enable ptrace for tracee.";
}

// Attach to the binary and wait for it to raise `SIGSTOP`.
static void TraceSubprocess(pid_t pid) {
  while (true) {
    auto status = 0;
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if (SIGSTOP == WSTOPSIG(status)) {
          break;
        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Unable to acquire control of tracee; it exited with signal "
              << WSTOPSIG(status);
        } else {
          LOG(INFO)
              << "Still trying to acquire control of tracee; "
              << "it stopped with signal " << WSTOPSIG(status);
        }
      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Unable to acquire control of tracee; it exited with status "
            << WEXITSTATUS(status);

      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Unable to acquire control of tracee; it terminated with signal "
            << WTERMSIG(status);
      } else {
        LOG(INFO)
            << "Unrecognized status " << status
            << " while trying to acquire control of tracee.";
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Problem waiting to acquire control of tracee: " << err;
    }
  }

  errno = 0;
  ptrace(PTRACE_SETOPTIONS, pid, 0,
         PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL);

  CHECK(ESRCH != errno)
      << "Unable to trace subprocess " << pid;
}

// Run until just after the `exec` system call.
static void RunUntilAfterExec(pid_t pid) {
  for (auto i = 0, status = 0; i < kMaxNumAttempts; ++i, status = 0) {
    errno = 0;
    ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if ((SIGTRAP | 0x80) == WSTOPSIG(status)) {
          return;
        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Tracee exited with signal " << WSTOPSIG(status)
              << " while doing exec of " << gTraceeArgv[0];
        } else {
          LOG(INFO)
              << "Tracee stopped with signal " << WSTOPSIG(status)
              << " while doing exec of " << gTraceeArgv[0];
        }
      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Tracee exited with status " << WEXITSTATUS(status)
            << " while doing exec of " << gTraceeArgv[0];

      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Tracee received signal " << WTERMSIG(status)
            << " while doing exec of " << gTraceeArgv[0] << ". "
            << "Maybe an invalid program was specified?";

      } else {
        LOG(INFO)
            << "Unrecognized status " << status
            << " while doing exec of " << gTraceeArgv[0];
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Problem during the exec of " << gTraceeArgv[0] << ": " << err;
    }
  }

  kill(pid, SIGKILL);
  LOG(FATAL)
      << "Exhausted maximum number of attempts to wait for exec of "
      << gTraceeArgv[0] << " to complete.";
}

// Run the tracee until just after it does an `execve`.
static void RunUntilInTracee(pid_t pid) {
  for (auto i = 0, status = 0; i < kMaxNumAttempts; ++i, status = 0) {
    ptrace(PTRACE_CONT, pid, 0, 0);
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
          LOG(INFO)
              << "Preparing to execute " << gTraceeArgv[0];
          RunUntilAfterExec(pid);
          return;

        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Tracee exited with signal " << WSTOPSIG(status)
              << " before doing exec of " << gTraceeArgv[0];
        } else {
          LOG(INFO)
              << "Tracee stopped with signal " << WSTOPSIG(status)
              << " before doing exec of " << gTraceeArgv[0];
        }

      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Tracee exited with status " << WEXITSTATUS(status)
            << " before doing exec of " << gTraceeArgv[0];

      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Tracee received signal " << WTERMSIG(status)
            << " before doing exec of " << gTraceeArgv[0];
      } else {
        LOG(INFO)
            << "Unrecognized status " << status << " received doing exec of "
            << gTraceeArgv[0];
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Problem entering the tracee: " << err;
    }
  }

  kill(pid, SIGKILL);
  LOG(FATAL)
      << "Exhausted maximum number of attempts to wait for the tracee "
      << "to exec into " << gTraceeArgv[0];
}

// Set a breakpoint on an address within the tracee.
static void RunUntilBreakpoint(pid_t pid) {
  LOG(INFO)
      << "Setting breakpoint at " << std::hex << FLAGS_breakpoint;

  errno = 0;
  auto old_text_word = ptrace(PTRACE_PEEKTEXT, pid, FLAGS_breakpoint, 0);
  auto has_err = 0 != errno;

  // Add in an `int3`.
  auto new_text_word = (old_text_word & (~0xFFL)) | 0xCCL;
  ptrace(PTRACE_POKETEXT, pid, FLAGS_breakpoint, new_text_word);

  if (has_err || 0 != errno) {
    kill(pid, SIGKILL);
    LOG(FATAL)
        << "Unable to write breakpoint at "
        << std::setw(16) << std::hex << std::setfill('0') << FLAGS_breakpoint
        << " into " << gTraceeArgv[0];
  }

  while (true) {  // Run until the breakpoint is hit.
    if (0 > ptrace(PTRACE_CONT, pid, 0, 0)) {
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Breakpoint won't be hit; unable to continue executing "
          << gTraceeArgv[0];
    }

    auto status = 0;
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if (SIGTRAP == WSTOPSIG(status)) {
          break;
        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Tracee exited with signal " << WSTOPSIG(status)
              << " before the breakpoint was hit.";
        } else {
          LOG(INFO)
              << "Tracee " << gTraceeArgv[0] << " received signal "
              << WSTOPSIG(status) << " before the breakpoint was hit.";
        }
      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Tracee " << gTraceeArgv[0]
            << " exited before breakpoint was hit";
      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Tracee " << gTraceeArgv[0]
            << " exited before breakpoint was hit";
      } else {
        LOG(INFO)
            << "Unrecognized status " << status << " received before "
            << "hitting breakpoint in " << gTraceeArgv[0];
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Problem waiting for the breakpoint in " << gTraceeArgv[0]
          << " to be hit: " << err;
    }
  }

  // Restore the original code.
  ptrace(PTRACE_POKETEXT, pid, FLAGS_breakpoint, old_text_word);
}

static uint64_t GetMaxStackSize(void) {
  static uint64_t max_stack_size = 0;
  if (!max_stack_size) {
    struct rlimit limit;
    getrlimit(RLIMIT_STACK, &limit);
    LOG(INFO)
        << "Current stack size limit is " << std::dec << limit.rlim_cur;

    uint64_t our_max = 16ULL << 20ULL;
    max_stack_size = std::max<uint64_t>(limit.rlim_cur, our_max);
    LOG(INFO)
        << "New stack size limit is " << std::dec << max_stack_size;
  }

  return max_stack_size;
}

// Gets the list of all thread IDs for this process.
static std::vector<pid_t> GetTIDs(pid_t pid) {
  std::vector<pid_t> tids;

  std::stringstream ss;
  ss << "/proc/" << pid << "/task/";

  auto dir = opendir(ss.str().c_str());
  CHECK(dir != nullptr)
      << "Could not list the " << ss.str() << " directory to find the thread "
      << "IDs";

  while (auto ent = readdir(dir)) {
    pid_t tid = -1;
    char dummy;
    if (sscanf(ent->d_name, "%d%c", &tid, &dummy) == 1 &&
        0 <= tid) {
      tids.push_back(tid);
    }
  }
  closedir(dir);
  return tids;
}

// Converts a line from `/proc/<pid>/maps` into a name that will be used as
// the file name for a file containing the actual data contained within the
// range.
static std::string PageRangeName(const std::string &line) {
  std::stringstream ss;
  auto seen_sym = false;
  for (auto c : line) {
    if (isalnum(c)) {
      ss << c;
      seen_sym = false;
    } else if ('\r' == c || '\n' == c) {
      break;
    } else if (!seen_sym) {
      ss << "_";
      seen_sym = true;
    }
  }
  return ss.str();
}

// Parse a line from `/proc/<pid>/maps` and fill in a `PageInfo` structure.
static bool ReadPageInfoLine(const std::string &line,
                             vmill::snapshot::AddressSpace *memory) {
  auto cline = line.c_str();
  uint64_t begin = 0;
  uint64_t end = 0;
  uint64_t offset = 0;
  unsigned dev_major = 0;
  unsigned dev_minor = 0;
  uint64_t inode = 0;
  struct stat;
  char r = '-';
  char w = '-';
  char x = '-';
  char p = '-';
  char path_mem[PATH_MAX + 1] = {};

  auto num_vars_read = sscanf(
      cline, "%" SCNx64 "-%" SCNx64 " %c%c%c%c %" SCNx64 " %x:%x %"
      SCNd64 "%s", &begin, &end, &r, &w, &x, &p, &offset, &dev_major,
      &dev_minor, &inode, &(path_mem[0]));

  if (!(10 == num_vars_read || 11 == num_vars_read)) {
    return false;
  }

  // Make sure that `path` points to the first non-space character in
  // `path_mem`.
  path_mem[PATH_MAX] = '\0';
  auto path = &(path_mem[0]);
  for (auto i = 0; i < PATH_MAX && path_mem[i] && ' ' == path_mem[i]; ++i) {
    path++;
  }

  auto info = memory->add_page_ranges();

  LOG(INFO)
      << "Page info: " << line;

  info->set_base(static_cast<int64_t>(begin));
  info->set_limit(static_cast<int64_t>(end));
  info->set_can_read('r' == r);
  info->set_can_write('w' == w);
  info->set_can_exec('x' == x);
  info->set_name(PageRangeName(line));

  if (strstr(path, "[stack]")) {
    info->set_kind(vmill::snapshot::kLinuxStackPageRange);

    auto curr_stack_size = end - begin;
    auto new_stack_size = std::max(curr_stack_size, GetMaxStackSize());

    info->set_base(static_cast<int64_t>(end - new_stack_size));

    LOG(INFO)
        << "New stack base is " << std::hex << info->base() << std::dec;

  } else if (strstr(path, "[vvar]")) {
    info->set_kind(vmill::snapshot::kLinuxVVarPageRange);

  } else if (strstr(path, "[vdso]")) {
    info->set_kind(vmill::snapshot::kLinuxVDSOPageRange);

  } else if (strstr(path, "[vsyscall]")) {
    info->set_kind(vmill::snapshot::kLinuxVSysCallPageRange);

  } else if (strstr(path, "[heap]")) {
    info->set_kind(vmill::snapshot::kLinuxHeapPageRange);

  } else if (path[0]) {
    info->set_kind(vmill::snapshot::kFileBackedPageRange);
    info->set_file_path(path);
    info->set_file_offset(static_cast<int64_t>(offset));

  } else {
    info->set_kind(vmill::snapshot::kAnonymousPageRange);
  }

  return true;
}

// Read out the ranges of mapped pages.
static void ReadTraceePageMaps(pid_t pid, vmill::snapshot::AddressSpace *memory) {
  std::stringstream ss;
  ss << "/proc/" << pid << "/maps";

  std::ifstream maps_file(ss.str());
  std::string line;
  while (std::getline(maps_file, line)) {
    LOG_IF(ERROR, !ReadPageInfoLine(line, memory))
        << "Unexpected format for page line: " << line;
  }
}

// Copy some data from the tracee into the snapshot file, using ptrace to do
// the copying.
static bool CopyTraceeMemoryWithPtrace(pid_t pid, uint64_t addr,
                                       uint64_t size, void *dest) {
  for (auto i = 0UL; i < size; ) {
    errno = 0;
    auto copied_data = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    if (errno) {
      return false;
    }

    auto dest_data = reinterpret_cast<decltype(copied_data) *>(dest);
    dest_data[i / sizeof(copied_data)] = copied_data;

    i += sizeof(copied_data);
    addr += sizeof(copied_data);
  }

  return true;
}

enum {
  kPageBuffSize = 4096
};

static char gPageBuff[kPageBuffSize];

// Copy memory from the tracee into the snapshot file.
static void CopyTraceeMemory(
    pid_t pid, const vmill::snapshot::AddressSpace *memory) {

  // Open up the file that maps in the processes's memory; succeeded is not
  // a strict requirement given the ptrace-based fallback.
  std::stringstream ss;
  ss << "/proc/" << pid << "/mem";
  std::string source_path = ss.str();
  auto mem_fd = open(source_path.c_str(), O_RDONLY);

  LOG_IF(ERROR, -1 == mem_fd)
      << "Can't open " << source_path << " for reading";

  for (const auto &info : memory->page_ranges()) {

    std::stringstream dest_path_ss;
    dest_path_ss << vmill::Workspace::MemoryDir()
                 << remill::PathSeparator()
                 << info.name();

    // Make sure the file that will contain the memory has the right size.
    std::string dest_path = dest_path_ss.str();
    auto dest_fd = open(dest_path.c_str(), O_RDWR | O_TRUNC | O_CREAT, 0666);
    CHECK(-1 != dest_fd)
        << "Can't open " << dest_path << " for writing.";

    auto size_to_copy = static_cast<uint64_t>(info.limit() - info.base());
    ftruncate(dest_fd, size_to_copy);

    uint64_t i = 0;

    // The mapping is originally file-backed. Start by copying in the original
    // backing data.
    if (info.kind() == vmill::snapshot::kFileBackedPageRange) {
      int mapped_file_fd = open(info.file_path().c_str(), O_RDONLY);
      if (-1 != mapped_file_fd) {
        lseek(mapped_file_fd, info.file_offset(), SEEK_SET);

        LOG(INFO)
            << "Copying " << std::dec << size_to_copy << " bytes from "
            << info.file_path() << " at offset " << std::hex
            << info.file_offset() << " into " << dest_path << std::dec;

        for (i = 0; i < size_to_copy; i += kPageBuffSize) {
          memset(gPageBuff, 0, kPageBuffSize);
          if (kPageBuffSize == read(mapped_file_fd, gPageBuff, kPageBuffSize)) {
            lseek(dest_fd, i, SEEK_SET);
            write(dest_fd, gPageBuff, kPageBuffSize);
          }
        }
      } else {
        LOG(ERROR)
            << "Unable to open " << info.file_path() << " for reading";
      }
      close(mapped_file_fd);
    }

    LOG(INFO)
        << "Copying " << std::dec << size_to_copy
        << " bytes from the tracee's memory (" << source_path << ") from "
        << std::hex << info.base() << " to " << std::hex << info.limit()
        << " into " << dest_path << std::dec;

    // Start by trying to copy from the `/proc/<pid>/mem` file.
    for (uint64_t i = 0; i < size_to_copy; i += kPageBuffSize) {
      auto page_addr = static_cast<uint64_t>(info.base()) + i;
      lseek(mem_fd, static_cast<int64_t>(page_addr), SEEK_SET);
      memset(gPageBuff, 0, kPageBuffSize);

      if (kPageBuffSize == read(mem_fd, gPageBuff, kPageBuffSize) ||
          CopyTraceeMemoryWithPtrace(pid, page_addr,
                                     kPageBuffSize, gPageBuff)) {
        lseek(dest_fd, i, SEEK_SET);
        write(dest_fd, gPageBuff, kPageBuffSize);
      } else {
        LOG(WARNING)
            << "Can't copy memory at offset " << std::hex << page_addr
            << std::dec;
      }
    }
    close(dest_fd);
  }
  close(mem_fd);
}

static void SaveSnapshotFile(void) {
  const auto &path = vmill::Workspace::SnapshotPath();
  std::ofstream snaphot_out(path);
  CHECK(snaphot_out)
      << "Unable to open " << path << " for writing";

  CHECK(gSnapshot.SerializePartialToOstream(&snaphot_out))
      << "Unable to serialize snapshot description to " << path;
}

// Create a snapshot file of the tracee.
static void SnapshotTracee(pid_t pid) {
  const auto &path = vmill::Workspace::SnapshotPath();
  int64_t memory_id = 1;

  auto memory = gSnapshot.add_address_spaces();
  memory->set_id(memory_id);

  ReadTraceePageMaps(pid, memory);
  CopyTraceeMemory(pid, memory);

  const auto arch_name = remill::GetTargetArch()->arch_name;
  for (auto tid : GetTIDs(pid)) {
    switch (arch_name) {
      case remill::kArchX86:
      case remill::kArchX86_AVX:
      case remill::kArchX86_AVX512:
        LOG(INFO)
            << "Writing X86 register state for thread " << std::dec
            << tid << " into " << path;
        vmill::CopyX86TraceeState(pid, tid, memory_id, &gSnapshot);
        break;
      case remill::kArchAMD64:
      case remill::kArchAMD64_AVX:
      case remill::kArchAMD64_AVX512:
        LOG(INFO)
            << "Writing AMD64 register state for thread " << std::dec
            << tid << " into " << path;
        vmill::CopyX86TraceeState(pid, tid, memory_id, &gSnapshot);
        break;

      case remill::kArchAArch64LittleEndian:
        LOG(INFO)
            << "Writing AArch64 register state for thread " << std::dec
            << tid << " into " << path;
        vmill::CopyAArch64TraceeState(pid, tid, memory_id, &gSnapshot);
        break;

      default:
        LOG(FATAL)
            << "Cannot copy tracee register state for unsupported architecture "
            << FLAGS_arch;
    }
  }
  SaveSnapshotFile();
}

// Change file descriptor properties to close normal FDs on `execve` in the
// tracee.
static void CloseFdsOnExec(void) {
  auto dp = opendir("/proc/self/fd");
  CHECK(nullptr != dp)
      << "Unable to open /proc/self/fd directory of tracee: "
      << strerror(errno);

  while (true) {
    errno = 0;
    auto dirent = readdir(dp);
    if (!dirent) {
      CHECK(!errno)
          << "Unable to list /proc/self/fd directory of tracee: "
          << strerror(errno);
      break;
    }

    int fd = 0;
    if (1 != sscanf(dirent->d_name, "%d", &fd)) {
      continue;
    }

    switch (fd) {
      case STDIN_FILENO:
      case STDOUT_FILENO:
      case STDERR_FILENO:
        break;
      default:
        LOG(INFO)
            << "Setting fd " << std::dec << fd << " to close on exec.";

        CHECK(!fcntl(fd, F_SETFD, FD_CLOEXEC))
            << "Unable to change fd " << fd << " in tracee to close on exec: "
            << strerror(errno);
        break;
    }
  }

  closedir(dp);
}

// Spawn a sub-process, execute the program up until a breakpoint is hit, and
// snapshot the program at that breakpoint.
static void SnapshotProgram(remill::ArchName arch, remill::OSName os) {
  signal(SIGCHLD, SIG_IGN);

  LogPrepareExec();

  if (const auto pid = fork()) {
    CHECK(-1 != pid)
        << "Could not fork process.";

    LOG(INFO)
        << "Acquiring control of tracee with pid " << pid;

    TraceSubprocess(pid);
    LOG(INFO)
        << "Acquired control of tracee with pid " << pid;

    RunUntilInTracee(pid);
    LOG(INFO)
        << "Tracee with pid " << pid << " is now running " << gTraceeArgv[0];

    if (FLAGS_breakpoint) {
      RunUntilBreakpoint(pid);
      LOG(INFO)
          << "Hit breakpoint at "
          << std::setw(16) << std::hex << std::setfill('0') << FLAGS_breakpoint
          << " in " << gTraceeArgv[0];
    }

    LOG(INFO)
        << "Snapshotting " << gTraceeArgv[0];

    SnapshotTracee(pid);

    kill(pid, SIGKILL);

  } else {
    signal(SIGCHLD, SIG_DFL);  // Restore  signal handler state.

    EnableTracing();
    CloseFdsOnExec();

    // Tell the tracee to load in all shared libraries as soon as possible.
    CHECK(!setenv("LD_BIND_NOW", "1", true))
        << "Unable to set LD_BIND_NOW=1 for tracee: " << strerror(errno);

    // Ideally speed up calls to `localtime`.
    if (!getenv("TZ")) {
      CHECK(!setenv("TZ", ":/etc/localtime", true))
          << "Unable to set TZ=\":/etc/localtime\" for tracee: "
          << strerror(errno);
    }

    CHECK(!execvpe(gTraceeArgv[0], gTraceeArgv, __environ))
        << "Unable to exec tracee: " << strerror(errno);
  }
}

}  // namespace

int main(int argc, char **argv) {

  // Extract the arguments to the tracee before gflags and glog get at them,
  // that way gflags/glog don't complain about invalid arguments.
  const auto got_tracee_args = ExtractTraceeArgs(&argc, argv);

  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --breakpoint ADDR \\" << std::endl
     << "    --workspace WORKSPACE_DIR \\" << std::endl
     << "    -- PROGRAM ..." << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

  CHECK(got_tracee_args)
      << "Unable to extract arguments to tracee. Make sure to provide "
      << "the program and command-line arguments to that program after "
      << "a '--'.";

  auto arch_name = remill::GetArchName(FLAGS_arch);
  CHECK(remill::kArchInvalid != arch_name)
      << "Invalid architecture name specified to --arch.";

  auto os_name = remill::GetOSName(FLAGS_os);
  CHECK(remill::kOSInvalid != os_name)
      << "Invalid operating system name specified to --os.";

  gSnapshot.set_arch(FLAGS_arch);
  gSnapshot.set_os(FLAGS_os);

  SnapshotProgram(arch_name, os_name);

  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}
