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
#ifndef TOOLS_VMILL_VMILL_UTIL_HASH_H_
#define TOOLS_VMILL_VMILL_UTIL_HASH_H_

#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>

#include "vmill/Etc/xxHash/xxhash.h"

namespace vmill {
namespace detail {

class XXH32Hasher {
 public:
  XXH32Hasher(uint32_t seed=0);
  void Update(const void * begin, size_t size);
  uint32_t Digest(void);

 private:
  XXH32_state_t state;
};

class XXH64Hasher {
 public:
  XXH64Hasher(uint64_t seed=0);
  void Update(const void * begin, size_t size);
  uint64_t Digest(void);
 private:
  XXH64_state_t state;
};

}  // namespace detail

template <typename T>
class Hasher;

template<>
class Hasher<uint32_t> : public detail::XXH32Hasher {
 public:
  using detail::XXH32Hasher::XXH32Hasher;
};

template<>
class Hasher<uint64_t> : public detail::XXH64Hasher {
 public:
  using detail::XXH64Hasher::XXH64Hasher;
};

uint64_t Hash(const void *data, size_t size);

inline uint64_t Hash(const std::string &data) {
  return Hash(data.data(), data.size());
}

template <typename T>
inline uint64_t Hash(const T &data) {
  return Hash(&data, sizeof(data));
}

}  // namespace vmill

#define VMILL_MAKE_STD_HASH_OVERRIDE(type) \
    namespace std { \
    template <> \
    struct hash<type> { \
     public: \
      using result_type = uint64_t; \
      using argument_type = type; \
      inline result_type operator()(const argument_type &val) const { \
        return vmill::Hash(val); \
      } \
    }; \
    }  // namespace std

#endif  // TOOLS_VMILL_VMILL_UTIL_HASH_H_
