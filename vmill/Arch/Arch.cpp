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

#include "remill/Arch/Arch.h"

#include "vmill/Arch/Arch.h"

namespace vmill {

extern void LogX86RegisterState(std::ostream &os, const ArchState *state_);
extern void LogAMD64RegisterState(std::ostream &os, const ArchState *state_);
extern void LogAArch64RegisterState(std::ostream &os, const ArchState *state_);

void LogRegisterState(std::ostream &os, const ArchState *state) {
  auto arch = remill::GetTargetArch();
  if (arch->IsX86()) {
    LogX86RegisterState(os, state);
  } else if (arch->IsAMD64()) {
    LogAMD64RegisterState(os, state);
  } else if (arch->IsAArch64()) {
    LogAArch64RegisterState(os, state);
  }
}

}  // namespace vmill
