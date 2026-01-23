#pragma once

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "w1instrument/config/tracer_common_config.hpp"
#include "w1base/env_config.hpp"

#if !defined(_WIN32)
extern "C" char** environ;
#endif

namespace w1::tracers::script {

struct script_config {
  w1::instrument::config::tracer_common_config common{};
  std::string script_path;
  std::unordered_map<std::string, std::string> script_args;

  static script_config from_environment() {
    w1::util::env_config loader("W1SCRIPT");

    script_config config;
    config.common = w1::instrument::config::load_common(loader);
    config.script_path = loader.get<std::string>("SCRIPT", "");

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
      if (suffix == "SCRIPT" || w1::instrument::config::is_common_reserved_key(suffix)) {
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
