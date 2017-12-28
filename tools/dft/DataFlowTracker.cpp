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

  enum Op: uint64_t {
    kOpInvalid,
    kOpConstant,
    kOpConvert,
    kOpBinary,
    kOpCompare,
    kOpSelect,
    kOpLoad,
    kOpStore,
    kOpAddressOfLocal,
    kOpAddressOfGlobal
  };

  enum Type : uint64_t {
    kTypeInt,
    kTypeFloat
  };

  uint64_t flat;
  struct {
    uint64_t tainted:1;
    Op op:4;
    Type type:2;
    uint64_t id:48;
  } __attribute__((packed)) op;

//  struct {
//    uint64_t tainted:1;
//    Op op:4;
//    uint64_t byte_val:8;
//  } __attribute__((packed)) load;
//
//  struct {
//    uint64_t tainted:1;
//    Op op:2;
//    Type type:2;
//    uint64_t offset:3;  // 0, 1, 2, 3, 4, 5, 6, 7.
//    uint64_t id:48;  // ID of the taint being written.
//  } __attribute__((packed)) store;

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
  res.op.tainted = 1;
  res.op.op = Tag::kOp;
  res.op.type = Tag::kType;
  res.op.id = Taint::gId++;
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

#define GET_FLOAT_BINOPS(name) \
    GET_BINOP(name, 32, f32); \
    GET_BINOP(name, 64, f64)

#define GET_INT_BINOPS(name) \
    GET_BINOP(name, 1, i1); \
    /*GET_BINOP(name, 2, i2); \
    GET_BINOP(name, 3, i3); \
    GET_BINOP(name, 4, i4); \
    GET_BINOP(name, 5, i5); \
    GET_BINOP(name, 6, i6); \
    GET_BINOP(name, 7, i7);*/ \
    GET_BINOP(name, 8, i8); \
    /*GET_BINOP(name, 9, i9); \
    GET_BINOP(name, 10, i10); \
    GET_BINOP(name, 11, i11); \
    GET_BINOP(name, 12, i12); \
    GET_BINOP(name, 13, i13); \
    GET_BINOP(name, 14, i14); \
    GET_BINOP(name, 15, i15); \
    GET_BINOP(name, 16, i16); \
    GET_BINOP(name, 17, i17); \
    GET_BINOP(name, 18, i18); \
    GET_BINOP(name, 19, i19); \
    GET_BINOP(name, 20, i20); \
    GET_BINOP(name, 21, i21); \
    GET_BINOP(name, 22, i22); \
    GET_BINOP(name, 23, i23); \
    GET_BINOP(name, 24, i24); \
    GET_BINOP(name, 25, i25); \
    GET_BINOP(name, 26, i26); \
    GET_BINOP(name, 27, i27); \
    GET_BINOP(name, 28, i28); \
    GET_BINOP(name, 29, i29); \
    GET_BINOP(name, 30, i30); \
    GET_BINOP(name, 31, i31);*/ \
    GET_BINOP(name, 32, i32); \
    /*GET_BINOP(name, 33, i33); \
    GET_BINOP(name, 34, i34); \
    GET_BINOP(name, 35, i35); \
    GET_BINOP(name, 36, i36); \
    GET_BINOP(name, 37, i37); \
    GET_BINOP(name, 38, i38); \
    GET_BINOP(name, 39, i39); \
    GET_BINOP(name, 40, i40); \
    GET_BINOP(name, 41, i41); \
    GET_BINOP(name, 42, i42); \
    GET_BINOP(name, 43, i43); \
    GET_BINOP(name, 44, i44); \
    GET_BINOP(name, 45, i45); \
    GET_BINOP(name, 46, i46); \
    GET_BINOP(name, 47, i47); \
    GET_BINOP(name, 48, i48); \
    GET_BINOP(name, 49, i49); \
    GET_BINOP(name, 50, i50); \
    GET_BINOP(name, 51, i51); \
    GET_BINOP(name, 52, i52); \
    GET_BINOP(name, 53, i53); \
    GET_BINOP(name, 54, i54); \
    GET_BINOP(name, 55, i55); \
    GET_BINOP(name, 56, i56); \
    GET_BINOP(name, 57, i57); \
    GET_BINOP(name, 58, i58); \
    GET_BINOP(name, 59, i59); \
    GET_BINOP(name, 60, i60); \
    GET_BINOP(name, 61, i61); \
    GET_BINOP(name, 62, i62); \
    GET_BINOP(name, 63, i63);*/ \
    GET_BINOP(name, 64, i64); \
    /*GET_BINOP(name, 65, i65); \
    GET_BINOP(name, 66, i66); \
    GET_BINOP(name, 67, i67); \
    GET_BINOP(name, 68, i68); \
    GET_BINOP(name, 69, i69); \
    GET_BINOP(name, 70, i70); \
    GET_BINOP(name, 71, i71); \
    GET_BINOP(name, 72, i72); \
    GET_BINOP(name, 73, i73); \
    GET_BINOP(name, 74, i74); \
    GET_BINOP(name, 75, i75); \
    GET_BINOP(name, 76, i76); \
    GET_BINOP(name, 77, i77); \
    GET_BINOP(name, 78, i78); \
    GET_BINOP(name, 79, i79); \
    GET_BINOP(name, 80, i80); \
    GET_BINOP(name, 81, i81); \
    GET_BINOP(name, 82, i82); \
    GET_BINOP(name, 83, i83); \
    GET_BINOP(name, 84, i84); \
    GET_BINOP(name, 85, i85); \
    GET_BINOP(name, 86, i86); \
    GET_BINOP(name, 87, i87); \
    GET_BINOP(name, 88, i88); \
    GET_BINOP(name, 89, i89); \
    GET_BINOP(name, 90, i90); \
    GET_BINOP(name, 91, i91); \
    GET_BINOP(name, 92, i92); \
    GET_BINOP(name, 93, i93); \
    GET_BINOP(name, 94, i94); \
    GET_BINOP(name, 95, i95); \
    GET_BINOP(name, 96, i96); \
    GET_BINOP(name, 97, i97); \
    GET_BINOP(name, 98, i98); \
    GET_BINOP(name, 99, i99); \
    GET_BINOP(name, 100, i100); \
    GET_BINOP(name, 101, i101); \
    GET_BINOP(name, 102, i102); \
    GET_BINOP(name, 103, i103); \
    GET_BINOP(name, 104, i104); \
    GET_BINOP(name, 105, i105); \
    GET_BINOP(name, 106, i106); \
    GET_BINOP(name, 107, i107); \
    GET_BINOP(name, 108, i108); \
    GET_BINOP(name, 109, i109); \
    GET_BINOP(name, 110, i110); \
    GET_BINOP(name, 111, i111); \
    GET_BINOP(name, 112, i112); \
    GET_BINOP(name, 113, i113); \
    GET_BINOP(name, 114, i114); \
    GET_BINOP(name, 115, i115); \
    GET_BINOP(name, 116, i116); \
    GET_BINOP(name, 117, i117); \
    GET_BINOP(name, 118, i118); \
    GET_BINOP(name, 119, i119); \
    GET_BINOP(name, 120, i120); \
    GET_BINOP(name, 121, i121); \
    GET_BINOP(name, 122, i122); \
    GET_BINOP(name, 123, i123); \
    GET_BINOP(name, 124, i124); \
    GET_BINOP(name, 125, i125); \
    GET_BINOP(name, 126, i126); \
    GET_BINOP(name, 127, i127);*/ \
    GET_BINOP(name, 128, i128)


#define GET_BINOP(name, type_size, llvm_type_name) \
    struct name ## _ ## llvm_type_name ## _tag { \
      /* static constexpr const char *kOpName = #name; */ \
      /* static constexpr const char *kTypeName = #llvm_type_name; */ \
      /* static constexpr size_t kSizeInBits = type_size; */ \
      static constexpr Taint::Op kOp = TAINT_OP; \
      static constexpr Taint::Type kType = OP_TYPE; \
    }

#define TAINT_OP Taint::kOpBinary
#define OP_TYPE Taint::kTypeInt

GET_INT_BINOPS(add);
GET_INT_BINOPS(sub);
GET_INT_BINOPS(mul);
GET_INT_BINOPS(udiv);
GET_INT_BINOPS(sdiv);
GET_INT_BINOPS(urem);
GET_INT_BINOPS(srem);
GET_INT_BINOPS(shl);
GET_INT_BINOPS(lshr);
GET_INT_BINOPS(ashr);
GET_INT_BINOPS(and);
GET_INT_BINOPS(or);
GET_INT_BINOPS(xor);

#undef OP_TYPE
#define OP_TYPE Taint::kTypeFloat

GET_FLOAT_BINOPS(fadd);
GET_FLOAT_BINOPS(fsub);
GET_FLOAT_BINOPS(fmul);
GET_FLOAT_BINOPS(fdiv);
GET_FLOAT_BINOPS(frem);

#undef TAINT_OP
#define TAINT_OP Taint::kOpCompare

#undef OP_TYPE
#define OP_TYPE Taint::kTypeInt

GET_INT_BINOPS(icmp_eq);
GET_INT_BINOPS(icmp_ne);
GET_INT_BINOPS(icmp_ugt);
GET_INT_BINOPS(icmp_uge);
GET_INT_BINOPS(icmp_ult);
GET_INT_BINOPS(icmp_ule);
GET_INT_BINOPS(icmp_sgt);
GET_INT_BINOPS(icmp_sge);
GET_INT_BINOPS(icmp_slt);
GET_INT_BINOPS(icmp_sle);

#undef OP_TYPE
#define OP_TYPE Taint::kTypeFloat

GET_FLOAT_BINOPS(fcmp_false);
GET_FLOAT_BINOPS(fcmp_oeq);
GET_FLOAT_BINOPS(fcmp_ogt);
GET_FLOAT_BINOPS(fcmp_oge);
GET_FLOAT_BINOPS(fcmp_olt);
GET_FLOAT_BINOPS(fcmp_ole);
GET_FLOAT_BINOPS(fcmp_one);
GET_FLOAT_BINOPS(fcmp_ord);
GET_FLOAT_BINOPS(fcmp_ueq);
GET_FLOAT_BINOPS(fcmp_ugt);
GET_FLOAT_BINOPS(fcmp_uge);
GET_FLOAT_BINOPS(fcmp_ult);
GET_FLOAT_BINOPS(fcmp_ule);
GET_FLOAT_BINOPS(fcmp_une);
GET_FLOAT_BINOPS(fcmp_uno);
GET_FLOAT_BINOPS(fcmp_true);

#undef OP_TYPE
#undef GET_BINOP
#undef TAINT_OP

class DataFlowTracker : public TaintTrackerTool {
 public:
  DataFlowTracker(void)
      : TaintTrackerTool(64),
        shadow_memory(ShadowMemory::Get()) {

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

#define GET_BINOP(name, type_size, llvm_type_name) \
    taint_trackers["__taint_" #name "_" #llvm_type_name] = \
        reinterpret_cast<uintptr_t>( \
            TaintBinary<name ## _ ## llvm_type_name ## _tag>)

    GET_INT_BINOPS(add);
    GET_INT_BINOPS(sub);
    GET_INT_BINOPS(mul);
    GET_INT_BINOPS(udiv);
    GET_INT_BINOPS(sdiv);
    GET_INT_BINOPS(urem);
    GET_INT_BINOPS(srem);
    GET_INT_BINOPS(shl);
    GET_INT_BINOPS(lshr);
    GET_INT_BINOPS(ashr);
    GET_INT_BINOPS(and);
    GET_INT_BINOPS(or);
    GET_INT_BINOPS(xor);

    GET_FLOAT_BINOPS(fadd);
    GET_FLOAT_BINOPS(fsub);
    GET_FLOAT_BINOPS(fmul);
    GET_FLOAT_BINOPS(fdiv);
    GET_FLOAT_BINOPS(frem);

    GET_INT_BINOPS(icmp_eq);
    GET_INT_BINOPS(icmp_ne);
    GET_INT_BINOPS(icmp_ugt);
    GET_INT_BINOPS(icmp_uge);
    GET_INT_BINOPS(icmp_ult);
    GET_INT_BINOPS(icmp_ule);
    GET_INT_BINOPS(icmp_sgt);
    GET_INT_BINOPS(icmp_sge);
    GET_INT_BINOPS(icmp_slt);
    GET_INT_BINOPS(icmp_sle);

    GET_FLOAT_BINOPS(fcmp_false);
    GET_FLOAT_BINOPS(fcmp_oeq);
    GET_FLOAT_BINOPS(fcmp_ogt);
    GET_FLOAT_BINOPS(fcmp_oge);
    GET_FLOAT_BINOPS(fcmp_olt);
    GET_FLOAT_BINOPS(fcmp_ole);
    GET_FLOAT_BINOPS(fcmp_one);
    GET_FLOAT_BINOPS(fcmp_ord);
    GET_FLOAT_BINOPS(fcmp_ueq);
    GET_FLOAT_BINOPS(fcmp_ugt);
    GET_FLOAT_BINOPS(fcmp_uge);
    GET_FLOAT_BINOPS(fcmp_ult);
    GET_FLOAT_BINOPS(fcmp_ule);
    GET_FLOAT_BINOPS(fcmp_une);
    GET_FLOAT_BINOPS(fcmp_uno);
    GET_FLOAT_BINOPS(fcmp_true);
  }

#undef GET_INT_BINOPS
#undef GET_FLOAT_BINOPS
#undef GET_BINOP

  virtual ~DataFlowTracker(void) {

  }

  // Called when lifted bitcode or the runtime needs to resolve an external
  // symbol. This overload is provided so that client tools can choose which
  // specific taint functions they want to override, and aren't required to
  // actually
  uint64_t FindSymbolForLinking(
      const std::string &name, uint64_t resolved) override {
    auto it = taint_trackers.find(name);
    if (it != taint_trackers.end()) {
      return it->second;
    }
    return TaintTrackerTool::FindSymbolForLinking(name, resolved);
  }

 private:
  std::unordered_map<std::string, uint64_t> taint_trackers;

  std::unique_ptr<ShadowMemory> shadow_memory;
};

}  // namespace

std::unique_ptr<Tool> CreateDataFlowTracker(void) {
  return std::unique_ptr<Tool>(new DataFlowTracker);
}

}  // namespace vmill
