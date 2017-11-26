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

static void __vmill_init_fpu_environ(State *state) {
  int new_round = 0;
  switch (state->fpcr.rmode) {
    case kFPURoundToNearestEven:  // RN (round nearest).
      new_round = FE_TONEAREST;
      break;
    case kFPURoundUpInf:  // RP (round toward plus infinity).
      new_round = FE_UPWARD;
      break;
    case kFPURoundDownNegInf:  // RM (round toward minus infinity).
      new_round = FE_DOWNWARD;
      break;
    case kFPURoundToZero:  // RZ (round toward zero).
      new_round = FE_TOWARDZERO;
      break;
  }
  fesetround(new_round);
}

}  // namespace
