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

#define ADDRESS_SIZE_BITS 32
#define HAS_FEATURE_AVX 0
#define HAS_FEATE_AVX512 0
#define VMILL_RUNTIME_X86 32
#define VMILL_RUNTIME

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cfenv>
#include <cfloat>
#include <cinttypes>
#include <climits>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>

#pragma clang diagnostic push
#pragma clang diagnostic disabled "-Wgnu-alignof-expression"

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/X86/Runtime/State.h"

#include "vmill/Runtime/Generic/Intrinsics.h"
#include "vmill/Runtime/Generic/Memory.cpp"
#include "vmill/Runtime/Generic/SystemCallABI.h"
#include "vmill/Runtime/Generic/X86.cpp"
#include "vmill/Runtime/Generic/Run.cpp"

#include "vmill/Runtime/Linux/Run.h"
#include "vmill/Runtime/Linux/X86.cpp"
#include "vmill/Runtime/Linux/Run.cpp"

#pragma clang diagnostic pop

