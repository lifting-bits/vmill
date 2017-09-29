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

// Called by the executor to allocate state.
extern "C" State *__vmill_allocate_state(void) {
  return new State;
}

// Called by the executor when it wants to run a thread.
extern "C" void __vmill_resume(State &state, addr_t pc, Memory *memory) {
  (void) __remill_jump(state, pc, memory);
}
