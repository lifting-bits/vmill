/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/ManagedStatic.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "vmill/Arch/Decoder.h"
#include "vmill/BC/Lifter.h"
#include "vmill/Memory/AddressSpace.h"

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_uint64(pc, 0, "Program counter of the specified instruction bytes.");

DEFINE_string(memory_at_pc, "",
              "Instruction bytes in memory that exists at `--pc` in memory.");

namespace microx {

static void Run(void) {
  std::shared_ptr<llvm::LLVMContext> context(new llvm::LLVMContext);
  auto lifter = vmill::Lifter::Create(context);

  const auto num_bytes = FLAGS_memory_at_pc.size() / 2;
  std::transform(FLAGS_memory_at_pc.begin(), FLAGS_memory_at_pc.end(),
                 FLAGS_memory_at_pc.begin(), tolower);

  vmill::AddressSpace space;
  space.AddMap(FLAGS_pc, num_bytes, true, true, true);

  for (uint64_t i = 0, j = 0; j < num_bytes; i += 2, j++) {
    const char hex_str[] = {
        FLAGS_memory_at_pc[i], FLAGS_memory_at_pc[i + 1], '\0'};

    unsigned byte = 0;
    CHECK(1 == sscanf(hex_str, "%x", &byte))
        << "Could not parse '" << hex_str << "' as a hexadecimal byte.";

    CHECK(space.TryWrite(FLAGS_pc + j, static_cast<uint8_t>(byte)))
        << "Unable to write " << std::hex << byte
        << " to " << std::hex << FLAGS_pc + i;
  }

  auto module = new llvm::Module("", *context);
  auto decoded_traces = vmill::DecodeTraces(space, FLAGS_pc);
  for (const auto &decoded_trace : decoded_traces) {
    auto lifted_func = lifter->LiftTraceIntoModule(decoded_trace, module);
    IF_LLVM_LT_50(lifted_func->dump();)
  }
//  auto sched = vmill::Schedule::Create();
//
//  sched->Enqueue(lifted_func.func);
}

}  // namespace microx

int main(int argc, char **argv) {

  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --arch ARCH_NAME \\" << std::endl
     << "    --os OS_NAME \\" << std::endl
     << "    --pc PROGRAM_COUNTER \\" << std::endl
     << "    --memory_at_pc HEX_ENCODED_INSTRUCTION_BYTES" << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

  CHECK(!FLAGS_arch.empty() && !FLAGS_os.empty())
      << "The architecture and OS names must not be empty.";

  // Take the target architecture from the snapshot file.
  const auto arch_name = remill::GetArchName(FLAGS_arch);
  CHECK(remill::kArchInvalid != arch_name)
      << "Invalid architecture " << FLAGS_arch;

  // Take the target OS from the snapshot file.
  const auto os_name = remill::GetOSName(FLAGS_os);
  CHECK(remill::kOSInvalid != os_name)
      << "Invalid OS " << FLAGS_os;

  CHECK(!(FLAGS_memory_at_pc.size() % 2))
      << "The `--memory_at_pc` have an even sized number of bytes. "
      << "For example, `--memory_at_pc 01d8`.";

  microx::Run();

  llvm::llvm_shutdown();
  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}
