/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef VMILL_UTIL_CALLBACK_H_
#define VMILL_UTIL_CALLBACK_H_

#include <cstdint>
#include <functional>

namespace vmill {

using ByteReaderCallback = std::function<bool(uint64_t, uint8_t *)>;

}  // namespace vmill

#endif  // VMILL_UTIL_CALLBACK_H_
