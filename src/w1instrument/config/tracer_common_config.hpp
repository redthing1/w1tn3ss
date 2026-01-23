#pragma once

#include <array>
#include <string_view>

#include "w1base/env_config.hpp"
#include "w1instrument/core/instrumentation_policy.hpp"

namespace w1::instrument::config {

enum class thread_attach_policy {
  main_only,
  auto_attach,
};

struct tracer_common_config {
  w1::core::instrumentation_policy instrumentation{};
  bool exclude_self = true;
  int verbose = 0;
};

inline w1::core::instrumentation_policy load_instrumentation_policy(w1::util::env_config& loader) {
  w1::core::instrumentation_policy policy{};
  using system_policy = w1::core::system_module_policy;

  system_policy system = system_policy::exclude_all;
  system = loader.get_enum<system_policy>(
      {
          {"exclude", system_policy::exclude_all},
          {"exclude_all", system_policy::exclude_all},
          {"none", system_policy::exclude_all},
          {"critical", system_policy::include_critical},
          {"include_critical", system_policy::include_critical},
          {"all", system_policy::include_all},
          {"include_all", system_policy::include_all},
          {"include", system_policy::include_all},
      },
      "SYSTEM_POLICY", system
  );

  policy.system_policy = system;
  policy.include_unnamed_modules = loader.get<bool>("INCLUDE_UNNAMED", false);
  policy.use_default_excludes = loader.get<bool>("USE_DEFAULT_EXCLUDES", true);
  policy.include_modules = loader.get_list("INCLUDE");
  policy.exclude_modules = loader.get_list("EXCLUDE");
  return policy;
}

inline tracer_common_config load_common(w1::util::env_config& loader) {
  tracer_common_config config;
  config.instrumentation = load_instrumentation_policy(loader);
  config.exclude_self = loader.get<bool>("EXCLUDE_SELF", true);
  config.verbose = loader.get<int>("VERBOSE", 0);
  return config;
}

inline thread_attach_policy load_thread_attach_policy(
    w1::util::env_config& loader, thread_attach_policy fallback = thread_attach_policy::auto_attach
) {
  return loader.get_enum<thread_attach_policy>(
      {
          {"main", thread_attach_policy::main_only},
          {"auto", thread_attach_policy::auto_attach},
      },
      "THREADS", fallback
  );
}

inline constexpr std::array<std::string_view, 8> common_reserved_keys() {
  return {
      "SYSTEM_POLICY", "INCLUDE_UNNAMED", "USE_DEFAULT_EXCLUDES", "INCLUDE", "EXCLUDE", "EXCLUDE_SELF",
      "VERBOSE",       "THREADS",
  };
}

inline bool is_common_reserved_key(std::string_view key) {
  for (auto entry : common_reserved_keys()) {
    if (entry == key) {
      return true;
    }
  }
  return false;
}

} // namespace w1::instrument::config
