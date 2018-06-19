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

#ifdef __linux__
# include <fcntl.h>
# include <sys/stat.h>
# include <pthread.h>
#endif // __linux__

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sys/ioctl.h>
#include <unistd.h>

#include "linux/kvm.h"

#include "tools/KVM/KVM.h"

#include "vmill/Runtime/Task.h"

namespace vmill {
namespace {

struct VM;

struct Emulator {
  int fd;
  std::unordered_map<int, std::shared_ptr<VM>> vms;
};

struct VM {
  std::weak_ptr<Emulator> emulator;
  int fd;
  uintptr_t tss_addr;
};

static std::unordered_map<int, std::shared_ptr<Emulator>> gEmus;
static std::unordered_map<int, std::weak_ptr<VM>> gVMs;

static uint32_t gMSRsToSave[] = {
  MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
  MSR_STAR,
//#ifdef CONFIG_X86_64
//  MSR_CSTAR, MSR_KERNEL_GS_BASE, MSR_SYSCALL_MASK, MSR_LSTAR,
//#endif
  MSR_IA32_TSC, MSR_IA32_CR_PAT, MSR_VM_HSAVE_PA,
  MSR_IA32_FEATURE_CONTROL, MSR_IA32_BNDCFGS, MSR_TSC_AUX,
  MSR_IA32_SPEC_CTRL, MSR_IA32_ARCH_CAPABILITIES
};

static int CreateEmulator(void) {
  auto fd = dup(STDIN_FILENO);
  if (-1 != fd) {
    gEmus[fd].reset(new Emulator);
    gEmus[fd]->fd = fd;
  }
  return fd;
}

DEF_WRAPPER(open, const char *path, int oflag, mode_t mode) {
  if (!strcmp("/dev/kvm", path)) {
    errno = 0;
    return CreateEmulator();
  } else {
    return open(path, oflag, mode);
  }
}

DEF_WRAPPER(close, int fd) {
  if (gEmus.count(fd)) {
    gEmus[fd].reset();
  }

  if (gVMs.count(fd)) {
    auto &vm = gVMs[fd];
    if (auto vm_ptr = vm.lock()) {
      if (auto emu_ptr = vm_ptr->emulator.lock()) {
        emu_ptr->vms.erase(vm_ptr->fd);
      }
    }
    vm.reset();
  }
  return close(fd);
}

static int CheckEmuExtension(uintptr_t ext) {
  switch (ext) {
//    case KVM_CAP_NR_MEMSLOTS:
//      return 32;

    case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
    case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
    case KVM_CAP_USER_MEMORY:
    case KVM_CAP_SET_TSS_ADDR:
    case KVM_CAP_EXT_CPUID:
    case KVM_CAP_MP_STATE:
      return 1;
//
//    case KVM_CAP_NR_VCPUS:
//      return 1;
//
//    case KVM_CAP_MAX_VCPUS:
//      return 256;

    default:
      return -1;
  }
}

static int CheckVMExtension(uintptr_t ext) {
  switch (ext) {
    case KVM_CAP_NR_VCPUS:
      return 1;

    case KVM_CAP_MAX_VCPUS:
      return 256;

    default:
      return -1;
  }
}

static int CreateVM(int emu_fd) {
  if (!gEmus.count(emu_fd)) {
    errno = EINVAL;
    return -1;
  }

  auto vm_fd = dup(emu_fd);
  if (-1 != vm_fd) {
    auto &emu = gEmus[emu_fd];
    emu->vms[vm_fd].reset(new VM);

    auto &vm = emu->vms[vm_fd];
    gVMs[vm_fd] = vm;
  }

  return vm_fd;
}

static int GetMSRIndexList(struct kvm_msr_list *msr_list) {
  if (!msr_list->nmsrs) {
    msr_list->nmsrs = static_cast<uint32_t>(
        sizeof(gMSRsToSave) / sizeof(gMSRsToSave[0]));
  } else {
    for (uint32_t i = 0; i < msr_list->nmsrs; ++i) {
      msr_list->indices[i] = gMSRsToSave[i];
    }
  }
  return 0;
}

DEF_WRAPPER(ioctl, int fd, uintptr_t a, uintptr_t b, uintptr_t c,
            uintptr_t d, uintptr_t e) {
  errno = 0;
  if (gEmus.count(fd)) {
    if (auto &emu_ptr = gEmus[fd]) {
      switch (static_cast<uint32_t>(a)) {
        case KVM_GET_API_VERSION:
          return 12;
        case KVM_CHECK_EXTENSION:
          return CheckEmuExtension(b);
        case KVM_CREATE_VM:
          return CreateVM(fd);
        case KVM_GET_MSR_INDEX_LIST:
          return GetMSRIndexList(reinterpret_cast<struct kvm_msr_list *>(b));
        default:
          break;
      }
    }
  } else if (gVMs.count(fd)) {
    if (auto vm_ptr = gVMs[fd].lock()) {
      switch (static_cast<uint32_t>(a)) {
        case KVM_CHECK_EXTENSION:
          return CheckVMExtension(b);
        case KVM_SET_TSS_ADDR:
          vm_ptr->tss_addr = b;
          return 0;
        case KVM_IOEVENTFD:
          LOG(WARNING)
              << "ioctl(" << fd << ", KVM_IOEVENTFD) ignored";
          return -1;
        default:
          break;
      }
    }
  }
  return ioctl(fd, a, b, c, d, e);
}

#ifdef __DARWIN_NSIG
int GetSignalBits(int __signo) {
  return __signo > __DARWIN_NSIG ? 0 : (1 << (__signo - 1));
}
#endif

class KVMTool : public Tool {
 public:
  KVMTool(void) {

#ifdef __DARWIN_NSIG
    ProvideSymbol("__sigbits", GetSignalBits);
#endif
#ifdef __linux__
    OfferSymbol("fstatat64", fstatat64);
    OfferSymbol("mknodat", mknodat);
    OfferSymbol("pthread_atfork", pthread_atfork);
#endif
    ProvideWrappedSymbol(open);
    ProvideSymbol("open64", open_wrapper::run);
    ProvideWrappedSymbol(close);
    ProvideWrappedSymbol(ioctl);
  }
};

}  // namespace

std::unique_ptr<Tool> CreateKVM(void) {
  return std::unique_ptr<Tool>(new KVMTool);
}

}  // namespace vmill
