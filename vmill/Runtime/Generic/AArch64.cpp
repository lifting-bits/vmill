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

namespace {

extern "C" Memory *__vmill_breakpoint(State *state, vmill::PC pc,
                                      Memory *memory) {
  asm volatile ("" :: "m"(state), "m"(pc), "m"(memory) : "memory");
  return memory;
}

static int __vmill_get_rounding_mode(const ArchState *state_) {
  auto state = reinterpret_cast<const State *>(state_);
  switch (state->fpcr.rmode) {
    case kFPURoundToNearestEven:  // RN (round nearest).
      return FE_TONEAREST;
    case kFPURoundUpInf:  // RP (round toward plus infinity).
      return FE_UPWARD;
    case kFPURoundDownNegInf:  // RM (round toward minus infinity).
      return FE_DOWNWARD;
    case kFPURoundToZero:  // RZ (round toward zero).
      return FE_TOWARDZERO;
  }
}

}  // namespace
