#pragma once

#include "engine/address_space.hpp"
#include "engine/types.hpp"

namespace p1ll::engine {

struct apply_options {
  bool verify = true;
  bool flush_icache = true;
  bool rollback_on_failure = true;
  bool allow_wx = false;
};

result<apply_report> apply_plan(address_space& space, const std::vector<plan_entry>& plan, const apply_options& options);

} // namespace p1ll::engine
