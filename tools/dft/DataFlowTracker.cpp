/*
 * Copyright (c) 2017 Trail of Bits, nc, Inc.
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

#include "DataFlowTracker.h"

#include "tools/taint/TaintTracker.h"

#include "vmill/Program/ShadowMemory.h"
#include "vmill/Util/Compiler.h"

#include <unordered_map>

namespace vmill {
namespace {

union Taint {
  static uint64_t gId;

  uint64_t flat;
  struct {
    uint64_t is_tainted:1;
    uint64_t sel:7;
    uint64_t val:48;
  } __attribute__((packed));

} __attribute__((packed));

static_assert(sizeof(Taint) == 8, "Invalid packing of `union Taint`.");

uint64_t Taint::gId = 0;

static Taint gArgs[32] = {};
static Taint gReturnTaint = {};

static void StoreArgTaint(uint32_t i, Taint val) {
  gArgs[i] = val;
}

static Taint LoadArgTaint(uint32_t i) {
  auto taint = gArgs[i];
  gArgs[i] = {};
  return taint;
}

static void StoreReturnTaint(Taint val) {
  gReturnTaint = val;
}

static Taint LoadReturnTaint(void) {
  auto taint = gReturnTaint;
  gReturnTaint = {};
  return taint;
}

template <typename Tag>
static Taint TaintBinary(Taint lhs, Taint rhs) {
  if (likely(0 == (1 & (lhs.flat | rhs.flat)))) {
    return {};
  }

  // TODO(pag): Some kind of logging.

  Taint res{};
  res.is_tainted = 1;
  res.sel = 0;
  res.val = Taint::gId++;
  return res;
}

static Taint TaintSelect(Taint cond_taint, bool cond, Taint true_taint,
                         Taint false_taint) {
  if (cond) {
    return true_taint;
  } else {
    return false_taint;
  }
}

static void TaintSwitch(Taint option_taint, uint64_t option,
                        const uint64_t *options_begin,
                        const uint64_t *options_end) {

}

static void TaintBranch(Taint taken_taint, bool taken) {

}

template <size_t kNumBytes>
static Taint TaintLoad(Taint addr_taint, uint64_t addr) {
  Taint taints[kNumBytes];
  Taint any_tainted = {};

  _Pragma("unroll")
  for (size_t i = 0; i < kNumBytes; i++) {
    auto taint = ShadowMemory::At<Taint>(addr + i);
    any_tainted.flat |= taint.flat;
    taints[i] = taint;
  }

  if (likely(0 == (1 & any_tainted.flat))) {
    return {};
  }

  size_t i = 0;
  Taint last_taint = {};
  last_taint.val = taints[0].val;

  _Pragma("unroll")
  for (const Taint &taint : taints) {
    if (taint.val != last_taint.val) {
      goto concat;
    }

    if (taint.sel != i) {
      goto concat;
    }
    ++i;
  }

  // TODO(pag): If `addr_taint` is tainted, then report that we're loading
  //            `last_taint` from the tainted address. In with this, we can
  //            even re-assign the var...

  // Loaded the low N bytes of something previously stored.
  return last_taint;

concat:

  // TODO(pag): Report the generation of a new taint ID.

  last_taint.val = Taint::gId++;
  return last_taint;
}

template <size_t kNumBytes>
static void TaintStore(Taint addr_taint, uint64_t addr, Taint val_taint) {
  if (likely(!val_taint.is_tainted)) {
    return;
  }

  _Pragma("unroll")
  for (size_t i = 0; i < kNumBytes; ++i) {
    val_taint.sel = i;
    ShadowMemory::At<Taint>(addr + i) = val_taint;
  }
}

static void TaintMemSet(Taint dest_addr_taint, uintptr_t dest_addr,
                        Taint val_taint, uintptr_t dest_val,
                        Taint size_taint, uintptr_t dest_size) {
  val_taint.sel = 0;
  for (size_t i = 0; i < dest_size; ++i) {
    ShadowMemory::At<Taint>(dest_addr + i) = val_taint;
  }
}

static void TaintMemCopy(Taint dest_addr_taint, uintptr_t dest_addr,
                         Taint src_addr_taint, uintptr_t src_addr,
                         Taint size_taint, uintptr_t dest_size) {
  for (size_t i = 0; i < dest_size; ++i) {
    ShadowMemory::At<Taint>(dest_addr + i) = \
        ShadowMemory::At<Taint>(src_addr + i);
  }
}

static void TaintMemMove(Taint dest_addr_taint, uintptr_t dest_addr,
                         Taint src_addr_taint, uintptr_t src_addr,
                         Taint size_taint, uintptr_t dest_size) {
  if (!dest_size) {
    return;

  } else if (dest_addr < src_addr) {
    for (size_t i = 0; i < dest_size; ++i) {
      ShadowMemory::At<Taint>(dest_addr + dest_size - i - 1) = \
          ShadowMemory::At<Taint>(src_addr + dest_size - i - 1);
    }

  } else {
    for (size_t i = 0; i < dest_size; ++i) {
      ShadowMemory::At<Taint>(dest_addr + i) = \
          ShadowMemory::At<Taint>(src_addr + i);
    }
  }
}

static Taint TaintAddress(uintptr_t address, uintptr_t size) {
  return {};
}

#define GET_FLOAT_OPS(name) \
    MAKE_TAINT_OP(name, 32, float); \
    MAKE_TAINT_OP(name, 64, double)

#define GET_INT_OPS(name) \
    MAKE_TAINT_OP(name, 1, i1); \
    MAKE_TAINT_OP(name, 2, i2); \
    MAKE_TAINT_OP(name, 3, i3); \
    MAKE_TAINT_OP(name, 4, i4); \
    MAKE_TAINT_OP(name, 5, i5); \
    MAKE_TAINT_OP(name, 6, i6); \
    MAKE_TAINT_OP(name, 7, i7); \
    MAKE_TAINT_OP(name, 8, i8); \
    MAKE_TAINT_OP(name, 9, i9); \
    MAKE_TAINT_OP(name, 10, i10); \
    MAKE_TAINT_OP(name, 11, i11); \
    MAKE_TAINT_OP(name, 12, i12); \
    MAKE_TAINT_OP(name, 13, i13); \
    MAKE_TAINT_OP(name, 14, i14); \
    MAKE_TAINT_OP(name, 15, i15); \
    MAKE_TAINT_OP(name, 16, i16); \
    MAKE_TAINT_OP(name, 17, i17); \
    MAKE_TAINT_OP(name, 18, i18); \
    MAKE_TAINT_OP(name, 19, i19); \
    MAKE_TAINT_OP(name, 20, i20); \
    MAKE_TAINT_OP(name, 21, i21); \
    MAKE_TAINT_OP(name, 22, i22); \
    MAKE_TAINT_OP(name, 23, i23); \
    MAKE_TAINT_OP(name, 24, i24); \
    MAKE_TAINT_OP(name, 25, i25); \
    MAKE_TAINT_OP(name, 26, i26); \
    MAKE_TAINT_OP(name, 27, i27); \
    MAKE_TAINT_OP(name, 28, i28); \
    MAKE_TAINT_OP(name, 29, i29); \
    MAKE_TAINT_OP(name, 30, i30); \
    MAKE_TAINT_OP(name, 31, i31); \
    MAKE_TAINT_OP(name, 32, i32); \
    /*MAKE_TAINT_OP(name, 33, i33); \
    MAKE_TAINT_OP(name, 34, i34); \
    MAKE_TAINT_OP(name, 35, i35); \
    MAKE_TAINT_OP(name, 36, i36); \
    MAKE_TAINT_OP(name, 37, i37); \
    MAKE_TAINT_OP(name, 38, i38); \
    MAKE_TAINT_OP(name, 39, i39); \
    MAKE_TAINT_OP(name, 40, i40); \
    MAKE_TAINT_OP(name, 41, i41); \
    MAKE_TAINT_OP(name, 42, i42); \
    MAKE_TAINT_OP(name, 43, i43); \
    MAKE_TAINT_OP(name, 44, i44); \
    MAKE_TAINT_OP(name, 45, i45); \
    MAKE_TAINT_OP(name, 46, i46); \
    MAKE_TAINT_OP(name, 47, i47); \
    MAKE_TAINT_OP(name, 48, i48); \
    MAKE_TAINT_OP(name, 49, i49); \
    MAKE_TAINT_OP(name, 50, i50); \
    MAKE_TAINT_OP(name, 51, i51); \
    MAKE_TAINT_OP(name, 52, i52); \
    MAKE_TAINT_OP(name, 53, i53); \
    MAKE_TAINT_OP(name, 54, i54); \
    MAKE_TAINT_OP(name, 55, i55); \
    MAKE_TAINT_OP(name, 56, i56); \
    MAKE_TAINT_OP(name, 57, i57); \
    MAKE_TAINT_OP(name, 58, i58); \
    MAKE_TAINT_OP(name, 59, i59); \
    MAKE_TAINT_OP(name, 60, i60); \
    MAKE_TAINT_OP(name, 61, i61); \
    MAKE_TAINT_OP(name, 62, i62); \
    MAKE_TAINT_OP(name, 63, i63);*/ \
    MAKE_TAINT_OP(name, 64, i64); \
    /*MAKE_TAINT_OP(name, 65, i65); \
    MAKE_TAINT_OP(name, 66, i66); \
    MAKE_TAINT_OP(name, 67, i67); \
    MAKE_TAINT_OP(name, 68, i68); \
    MAKE_TAINT_OP(name, 69, i69); \
    MAKE_TAINT_OP(name, 70, i70); \
    MAKE_TAINT_OP(name, 71, i71); \
    MAKE_TAINT_OP(name, 72, i72); \
    MAKE_TAINT_OP(name, 73, i73); \
    MAKE_TAINT_OP(name, 74, i74); \
    MAKE_TAINT_OP(name, 75, i75); \
    MAKE_TAINT_OP(name, 76, i76); \
    MAKE_TAINT_OP(name, 77, i77); \
    MAKE_TAINT_OP(name, 78, i78); \
    MAKE_TAINT_OP(name, 79, i79); \
    MAKE_TAINT_OP(name, 80, i80); \
    MAKE_TAINT_OP(name, 81, i81); \
    MAKE_TAINT_OP(name, 82, i82); \
    MAKE_TAINT_OP(name, 83, i83); \
    MAKE_TAINT_OP(name, 84, i84); \
    MAKE_TAINT_OP(name, 85, i85); \
    MAKE_TAINT_OP(name, 86, i86); \
    MAKE_TAINT_OP(name, 87, i87); \
    MAKE_TAINT_OP(name, 88, i88); \
    MAKE_TAINT_OP(name, 89, i89); \
    MAKE_TAINT_OP(name, 90, i90); \
    MAKE_TAINT_OP(name, 91, i91); \
    MAKE_TAINT_OP(name, 92, i92); \
    MAKE_TAINT_OP(name, 93, i93); \
    MAKE_TAINT_OP(name, 94, i94); \
    MAKE_TAINT_OP(name, 95, i95); \
    MAKE_TAINT_OP(name, 96, i96); \
    MAKE_TAINT_OP(name, 97, i97); \
    MAKE_TAINT_OP(name, 98, i98); \
    MAKE_TAINT_OP(name, 99, i99); \
    MAKE_TAINT_OP(name, 100, i100); \
    MAKE_TAINT_OP(name, 101, i101); \
    MAKE_TAINT_OP(name, 102, i102); \
    MAKE_TAINT_OP(name, 103, i103); \
    MAKE_TAINT_OP(name, 104, i104); \
    MAKE_TAINT_OP(name, 105, i105); \
    MAKE_TAINT_OP(name, 106, i106); \
    MAKE_TAINT_OP(name, 107, i107); \
    MAKE_TAINT_OP(name, 108, i108); \
    MAKE_TAINT_OP(name, 109, i109); \
    MAKE_TAINT_OP(name, 110, i110); \
    MAKE_TAINT_OP(name, 111, i111); \
    MAKE_TAINT_OP(name, 112, i112); \
    MAKE_TAINT_OP(name, 113, i113); \
    MAKE_TAINT_OP(name, 114, i114); \
    MAKE_TAINT_OP(name, 115, i115); \
    MAKE_TAINT_OP(name, 116, i116); \
    MAKE_TAINT_OP(name, 117, i117); \
    MAKE_TAINT_OP(name, 118, i118); \
    MAKE_TAINT_OP(name, 119, i119); \
    MAKE_TAINT_OP(name, 120, i120); \
    MAKE_TAINT_OP(name, 121, i121); \
    MAKE_TAINT_OP(name, 122, i122); \
    MAKE_TAINT_OP(name, 123, i123); \
    MAKE_TAINT_OP(name, 124, i124); \
    MAKE_TAINT_OP(name, 125, i125); \
    MAKE_TAINT_OP(name, 126, i126); \
    MAKE_TAINT_OP(name, 127, i127);*/ \
    MAKE_TAINT_OP(name, 128, i128)


#define MAKE_TAINT_OP(name, type_size, llvm_type_name) \
    struct name ## _ ## llvm_type_name ## _tag { \
      /* static constexpr const char *kOpName = #name; */ \
      /* static constexpr const char *kTypeName = #llvm_type_name; */ \
      /* static constexpr size_t kSizeInBits = type_size; */ \
    }

GET_INT_OPS(add);
GET_INT_OPS(sub);
GET_INT_OPS(mul);
GET_INT_OPS(udiv);
GET_INT_OPS(sdiv);
GET_INT_OPS(urem);
GET_INT_OPS(srem);
GET_INT_OPS(shl);
GET_INT_OPS(lshr);
GET_INT_OPS(ashr);
GET_INT_OPS(and);
GET_INT_OPS(or);
GET_INT_OPS(xor);

GET_FLOAT_OPS(fadd);
GET_FLOAT_OPS(fsub);
GET_FLOAT_OPS(fmul);
GET_FLOAT_OPS(fdiv);
GET_FLOAT_OPS(frem);

GET_INT_OPS(icmp_eq);
GET_INT_OPS(icmp_ne);
GET_INT_OPS(icmp_ugt);
GET_INT_OPS(icmp_uge);
GET_INT_OPS(icmp_ult);
GET_INT_OPS(icmp_ule);
GET_INT_OPS(icmp_sgt);
GET_INT_OPS(icmp_sge);
GET_INT_OPS(icmp_slt);
GET_INT_OPS(icmp_sle);

GET_FLOAT_OPS(fcmp_false);
GET_FLOAT_OPS(fcmp_oeq);
GET_FLOAT_OPS(fcmp_ogt);
GET_FLOAT_OPS(fcmp_oge);
GET_FLOAT_OPS(fcmp_olt);
GET_FLOAT_OPS(fcmp_ole);
GET_FLOAT_OPS(fcmp_one);
GET_FLOAT_OPS(fcmp_ord);
GET_FLOAT_OPS(fcmp_ueq);
GET_FLOAT_OPS(fcmp_ugt);
GET_FLOAT_OPS(fcmp_uge);
GET_FLOAT_OPS(fcmp_ult);
GET_FLOAT_OPS(fcmp_ule);
GET_FLOAT_OPS(fcmp_une);
GET_FLOAT_OPS(fcmp_uno);
GET_FLOAT_OPS(fcmp_true);

#undef MAKE_TAINT_OP
#undef TAINT_OP

class DataFlowTracker : public TaintTrackerTool {
 public:
  DataFlowTracker(void)
      : TaintTrackerTool(64),
        shadow_memory(nullptr),
        constant_pool(kAreaRW, 0) {

    taint_trackers["__taint_load_arg"] = \
        reinterpret_cast<uintptr_t>(LoadArgTaint);
    taint_trackers["__taint_load_ret"] = \
        reinterpret_cast<uintptr_t>(LoadReturnTaint);

    taint_trackers["__taint_store_arg"] = \
        reinterpret_cast<uintptr_t>(StoreArgTaint);
    taint_trackers["__taint_store_ret"] = \
        reinterpret_cast<uintptr_t>(StoreReturnTaint);

    taint_trackers["__taint_select"] = \
        reinterpret_cast<uintptr_t>(TaintSelect);

    taint_trackers["__taint_switch"] = \
        reinterpret_cast<uintptr_t>(TaintSwitch);

    taint_trackers["__taint_branch"] = \
        reinterpret_cast<uintptr_t>(TaintBranch);

    taint_trackers["__taint_local"] = \
        reinterpret_cast<uintptr_t>(TaintAddress);

    taint_trackers["__taint_global"] = \
        reinterpret_cast<uintptr_t>(TaintAddress);

    taint_trackers["__taint_load_8"] = \
        reinterpret_cast<uintptr_t>(TaintLoad<1>);
    taint_trackers["__taint_load_16"] = \
        reinterpret_cast<uintptr_t>(TaintLoad<2>);
    taint_trackers["__taint_load_32"] = \
        reinterpret_cast<uintptr_t>(TaintLoad<4>);
    taint_trackers["__taint_load_64"] = \
        reinterpret_cast<uintptr_t>(TaintLoad<8>);
    taint_trackers["__taint_load_128"] = \
        reinterpret_cast<uintptr_t>(TaintLoad<16>);

    taint_trackers["__taint_store_8"] = \
        reinterpret_cast<uintptr_t>(TaintStore<1>);
    taint_trackers["__taint_store_16"] = \
        reinterpret_cast<uintptr_t>(TaintStore<2>);
    taint_trackers["__taint_store_32"] = \
        reinterpret_cast<uintptr_t>(TaintStore<4>);
    taint_trackers["__taint_store_64"] = \
        reinterpret_cast<uintptr_t>(TaintStore<8>);
    taint_trackers["__taint_store_128"] = \
        reinterpret_cast<uintptr_t>(TaintStore<16>);

    taint_trackers["__taint_memset"] = \
        reinterpret_cast<uintptr_t>(TaintMemSet);

    taint_trackers["__taint_memcpy"] = \
        reinterpret_cast<uintptr_t>(TaintMemCopy);

    taint_trackers["__taint_memmove"] = \
        reinterpret_cast<uintptr_t>(TaintMemMove);


#define MAKE_TAINT_OP(name, type_size, llvm_type_name) \
    taint_trackers["__taint_" #name "_" #llvm_type_name] = \
        reinterpret_cast<uintptr_t>( \
            TaintBinary<name ## _ ## llvm_type_name ## _tag>)

    GET_INT_OPS(add);
    GET_INT_OPS(sub);
    GET_INT_OPS(mul);
    GET_INT_OPS(udiv);
    GET_INT_OPS(sdiv);
    GET_INT_OPS(urem);
    GET_INT_OPS(srem);
    GET_INT_OPS(shl);
    GET_INT_OPS(lshr);
    GET_INT_OPS(ashr);
    GET_INT_OPS(and);
    GET_INT_OPS(or);
    GET_INT_OPS(xor);

    GET_FLOAT_OPS(fadd);
    GET_FLOAT_OPS(fsub);
    GET_FLOAT_OPS(fmul);
    GET_FLOAT_OPS(fdiv);
    GET_FLOAT_OPS(frem);

    GET_INT_OPS(icmp_eq);
    GET_INT_OPS(icmp_ne);
    GET_INT_OPS(icmp_ugt);
    GET_INT_OPS(icmp_uge);
    GET_INT_OPS(icmp_ult);
    GET_INT_OPS(icmp_ule);
    GET_INT_OPS(icmp_sgt);
    GET_INT_OPS(icmp_sge);
    GET_INT_OPS(icmp_slt);
    GET_INT_OPS(icmp_sle);

    GET_FLOAT_OPS(fcmp_false);
    GET_FLOAT_OPS(fcmp_oeq);
    GET_FLOAT_OPS(fcmp_ogt);
    GET_FLOAT_OPS(fcmp_oge);
    GET_FLOAT_OPS(fcmp_olt);
    GET_FLOAT_OPS(fcmp_ole);
    GET_FLOAT_OPS(fcmp_one);
    GET_FLOAT_OPS(fcmp_ord);
    GET_FLOAT_OPS(fcmp_ueq);
    GET_FLOAT_OPS(fcmp_ugt);
    GET_FLOAT_OPS(fcmp_uge);
    GET_FLOAT_OPS(fcmp_ult);
    GET_FLOAT_OPS(fcmp_ule);
    GET_FLOAT_OPS(fcmp_une);
    GET_FLOAT_OPS(fcmp_uno);
    GET_FLOAT_OPS(fcmp_true);
  }

#undef GET_INT_OPS
#undef GET_FLOAT_OPS
#undef MAKE_TAINT_OP

  virtual ~DataFlowTracker(void) {

  }

  void SetUp(void) override {
    shadow_memory = ShadowMemory::Get();
  }

  void TearDown(void) override {
    ShadowMemory::Put(shadow_memory);
  }

  uintptr_t FindIntConstantTaint(uint64_t const_val) override {
    auto taint = constant_pool.Allocate<Taint>();
    taint->is_tainted = false;
    taint->val = Taint::gId++;
    // TODO(pag): Logging of `const_val` or something.
    return reinterpret_cast<uintptr_t>(taint);
  }

  uintptr_t FindFloatConstantTaint(float const_val) override {
    auto taint = constant_pool.Allocate<Taint>();
    taint->is_tainted = false;
    taint->val = Taint::gId++;
    // TODO(pag): Logging of `const_val` or something.
    return reinterpret_cast<uintptr_t>(taint);
  }

  uintptr_t FindDoubleConstantTaint(double const_val) override {
    auto taint = constant_pool.Allocate<Taint>();
    taint->is_tainted = false;
    taint->val = Taint::gId++;
    // TODO(pag): Logging of `const_val` or something.
    return reinterpret_cast<uintptr_t>(taint);
  }

  uintptr_t FindTaintTransferFunc(const std::string &name) override {
    auto it = taint_trackers.find(name);
    if (it != taint_trackers.end()) {
      return it->second;
    } else {
      return 0;
    }
  }

 private:
  std::unordered_map<std::string, uintptr_t> taint_trackers;

  std::unique_ptr<ShadowMemory> shadow_memory;

  AreaAllocator constant_pool;
};

}  // namespace

std::unique_ptr<Tool> CreateDataFlowTracker(void) {
  return std::unique_ptr<Tool>(new DataFlowTracker);
}

}  // namespace vmill
