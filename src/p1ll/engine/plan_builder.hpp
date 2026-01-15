#pragma once

#include "engine/address_space.hpp"
#include "engine/types.hpp"
#include "engine/platform/platform.hpp"
#include <unordered_map>

namespace p1ll::engine {

class plan_builder {
public:
  plan_builder(const address_space& space, platform::platform_key platform_key);

  result<std::vector<plan_entry>> build(const recipe& recipe);

private:
  const address_space& space_;
  platform::platform_key platform_;

  result<bool> platform_allowed(const std::vector<std::string>& selectors) const;
};

} // namespace p1ll::engine
