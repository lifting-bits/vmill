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

#include "vmill/Util/Hash.h"

namespace vmill {
namespace detail {

XXH32Hasher::XXH32Hasher(uint32_t seed) {
  XXH32_reset(&state, seed);
}

void XXH32Hasher::Update(const void * begin, size_t size) {
  XXH32_update(&state, begin, size);
}

uint32_t XXH32Hasher::Digest(void) {
  return XXH32_digest(&state);
}

XXH64Hasher::XXH64Hasher(uint64_t seed) {
  XXH64_reset(&state, seed);
}

void XXH64Hasher::Update(const void * begin, size_t size) {
  XXH64_update(&state, begin, size);
}

uint64_t XXH64Hasher::Digest(void) {
  return XXH64_digest(&state);
}

}  // namespace detail

uint64_t Hash(const void *data, size_t size) {
  return XXH64(data, size, 0);
}

}  // namespace vmill
