#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "p1ll/engine/platform/platform.hpp"
#include "p1ll/engine/result.hpp"

namespace p1ll::heur {

enum class policy { strict, balanced, durable };

struct signature {
  std::string pattern;
  std::string pretty;
  size_t instruction_count = 0;
  size_t fixed_bytes = 0;
};

engine::result<signature> code_signature(
    std::span<const uint8_t> bytes,
    uint64_t address,
    const engine::platform::platform_key& platform,
    policy policy_value = policy::balanced
);

} // namespace p1ll::heur
