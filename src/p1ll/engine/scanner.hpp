#pragma once

#include "engine/address_space.hpp"
#include "engine/pattern.hpp"
#include "engine/types.hpp"

namespace p1ll::engine {

class scanner {
public:
  explicit scanner(const address_space& space);

  result<std::vector<scan_result>> scan(const pattern& signature, const scan_options& options) const;

private:
  const address_space& space_;
};

} // namespace p1ll::engine
