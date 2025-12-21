#pragma once

#include <string>
#include <vector>

#include "w1tn3ss/runtime/module_registry.hpp"

namespace w1::core {

enum class system_module_policy {
  exclude_all,
  include_critical,
  include_all
};

struct instrumentation_policy {
  system_module_policy system_policy = system_module_policy::exclude_all;
  bool include_unnamed_modules = false;
  bool use_default_excludes = true;
  std::vector<std::string> include_modules;
  std::vector<std::string> exclude_modules;

  bool should_instrument(const runtime::module_info& module) const;
};

} // namespace w1::core
