#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace w1replay::gdb {

bool merge_memory_bytes(
    const std::vector<std::optional<uint8_t>>& recorded,
    const std::vector<std::byte>& module_bytes,
    bool module_ok,
    std::span<std::byte> out
);

} // namespace w1replay::gdb
