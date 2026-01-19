#pragma once

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "w1instrument/core/instrumentation_policy.hpp"
#include "w1base/env_config.hpp"

#if !defined(_WIN32)
extern "C" char** environ;
#endif

namespace w1::tracers::script {

struct script_config {
  w1::core::instrumentation_policy instrumentation{};
  bool exclude_self = true;
  std::string script_path;
  int verbose = 0;
  std::unordered_map<std::string, std::string> script_args;

  static script_config from_environment() {
    w1::util::env_config loader("W1SCRIPT");

    script_config config;
    using system_policy = w1::core::system_module_policy;
    system_policy policy = system_policy::exclude_all;
    policy = loader.get_enum<system_policy>(
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
        "SYSTEM_POLICY", policy
    );
    config.instrumentation.system_policy = policy;
    config.instrumentation.include_unnamed_modules = loader.get<bool>("INCLUDE_UNNAMED", false);
    config.instrumentation.use_default_excludes = loader.get<bool>("USE_DEFAULT_EXCLUDES", true);
    config.instrumentation.include_modules = loader.get_list("INCLUDE");
    config.instrumentation.exclude_modules = loader.get_list("EXCLUDE");
    config.exclude_self = loader.get<bool>("EXCLUDE_SELF", true);

    config.script_path = loader.get<std::string>("SCRIPT", "");
    config.verbose = loader.get<int>("VERBOSE", 0);

    const std::unordered_set<std::string> reserved = {
        "SCRIPT",  "VERBOSE", "SYSTEM_POLICY", "INCLUDE_UNNAMED", "USE_DEFAULT_EXCLUDES",
        "INCLUDE", "EXCLUDE", "EXCLUDE_SELF",
    };

    auto env_vars = []() -> std::vector<std::string_view> {
      std::vector<std::string_view> values;
#if defined(_WIN32)
      char** env = _environ;
#else
      char** env = environ;
#endif
      if (!env) {
        return values;
      }
      for (char** entry = env; *entry != nullptr; ++entry) {
        values.emplace_back(*entry);
      }
      return values;
    }();

    for (const auto& entry : env_vars) {
      auto pos = entry.find('=');
      if (pos == std::string_view::npos) {
        continue;
      }
      std::string_view key = entry.substr(0, pos);
      std::string_view value = entry.substr(pos + 1);

      constexpr std::string_view prefix = "W1SCRIPT_";
      if (key.size() <= prefix.size() || key.substr(0, prefix.size()) != prefix) {
        continue;
      }

      std::string suffix(key.substr(prefix.size()));
      if (reserved.find(suffix) != reserved.end()) {
        continue;
      }

      std::string lower_key = suffix;
      std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
      });
      config.script_args[lower_key] = std::string(value);
    }

    return config;
  }

  bool is_valid() const { return !script_path.empty(); }
};

} // namespace w1::tracers::script
