#pragma once

#include "w1tn3ss/core/instrumentation_policy.hpp"
#include "w1tn3ss/util/module_identity.hpp"

namespace w1::util {

inline void append_self_excludes(core::instrumentation_policy& policy, const void* address) {
  module_identity identity = module_identity_from_address(address);
  if (!identity.path.empty()) {
    policy.exclude_modules.push_back(identity.path);
  }
  if (!identity.name.empty()) {
    policy.exclude_modules.push_back(identity.name);
  }
}

} // namespace w1::util
