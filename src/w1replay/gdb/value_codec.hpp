#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace w1replay::gdb {

enum class endian { little };

bool encode_uint64(uint64_t value, size_t size, std::span<std::byte> out, endian order = endian::little);

} // namespace w1replay::gdb
