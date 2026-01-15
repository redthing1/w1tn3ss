#pragma once

#include "engine/address_space.hpp"
#include "engine/apply.hpp"
#include "engine/plan_builder.hpp"
#include "engine/pattern.hpp"
#include "engine/scanner.hpp"
#include "engine/types.hpp"
#include "engine/platform/platform.hpp"
#include <memory>
#include <span>
#include <string_view>

namespace p1ll::engine {

class session {
public:
  static session for_process();
  static session for_buffer(std::span<uint8_t> buffer);
  static session for_buffer(std::span<uint8_t> buffer, platform::platform_key platform_override);

  bool is_dynamic() const noexcept { return dynamic_; }
  bool is_static() const noexcept { return !dynamic_; }

  const platform::platform_key& platform_key() const noexcept { return platform_; }

  result<std::vector<memory_region>> regions(const scan_filter& filter) const;
  result<std::vector<scan_result>> scan(std::string_view pattern, const scan_options& options) const;
  result<std::vector<plan_entry>> plan(const recipe& recipe) const;
  result<apply_report> apply(const std::vector<plan_entry>& plan, const apply_options& options = {});

private:
  session(std::unique_ptr<address_space> space, platform::platform_key platform_key, bool dynamic);

  std::unique_ptr<address_space> space_;
  platform::platform_key platform_;
  bool dynamic_ = true;
};

} // namespace p1ll::engine
