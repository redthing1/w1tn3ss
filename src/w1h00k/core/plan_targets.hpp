#pragma once

#include "w1h00k/backend/backend.hpp"

namespace w1::h00k::core {

template <typename Fn>
inline void for_each_plan_target(const backend::hook_plan& plan, Fn&& fn) {
  if (!plan.patches.empty()) {
    for (const auto& entry : plan.patches) {
      if (entry.target) {
        fn(entry.target);
      }
    }
    return;
  }
  if (plan.resolved_target) {
    fn(plan.resolved_target);
  }
}

} // namespace w1::h00k::core
