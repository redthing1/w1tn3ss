#pragma once

#include <string_view>

#include "p1ll/engine/platform/platform.hpp"
#include "p1ll/engine/result.hpp"

namespace p1llx::commands {

inline p1ll::engine::result<p1ll::engine::platform::platform_key> resolve_platform(
    std::string_view platform_override, bool require_arch = true
) {
  if (platform_override.empty()) {
    return p1ll::engine::ok_result(p1ll::engine::platform::detect_platform());
  }

  auto parsed = p1ll::engine::platform::parse_platform(platform_override);
  if (!parsed.ok()) {
    return p1ll::engine::error_result<p1ll::engine::platform::platform_key>(
        parsed.status_info.code,
        parsed.status_info.message
    );
  }

  if (require_arch && (parsed.value.arch.empty() || parsed.value.arch == "*")) {
    return p1ll::engine::error_result<p1ll::engine::platform::platform_key>(
        p1ll::engine::error_code::invalid_argument,
        "platform override must include a concrete arch"
    );
  }

  return parsed;
}

} // namespace p1llx::commands
