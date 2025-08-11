#pragma once

#include <string>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>
#include <optional>
#include "../p1ll/scripting/script_engine_factory.hpp"

namespace p01s0n {

struct p01s0n_config {
  int verbose = 0;
  std::string script_path = "";

  enum class config_source { none, config_file, auto_discovery, environment };

  config_source source = config_source::none;

  static p01s0n_config from_environment() {
    p01s0n_config config;
    config.source = config_source::environment;

    const char* verbose_env = std::getenv("POISON_VERBOSE");
    if (verbose_env) {
      config.verbose = std::atoi(verbose_env);
    }

    const char* script_env = std::getenv("POISON_CURE");
    if (script_env) {
      config.script_path = script_env;
    }

    return config;
  }

  static std::optional<p01s0n_config> from_config_file(const std::string& config_path = "p01s0n.conf") {
    if (!std::filesystem::exists(config_path)) {
      return std::nullopt;
    }

    std::ifstream file(config_path);
    if (!file.is_open()) {
      return std::nullopt;
    }

    p01s0n_config config;
    config.source = config_source::config_file;
    std::string line;

    while (std::getline(file, line)) {
      if (line.empty() || line[0] == '#') {
        continue;
      }

      auto pos = line.find('=');
      if (pos == std::string::npos) {
        continue;
      }

      std::string key = line.substr(0, pos);
      std::string value = line.substr(pos + 1);

      // trim whitespace
      key.erase(0, key.find_first_not_of(" \t"));
      key.erase(key.find_last_not_of(" \t") + 1);
      value.erase(0, value.find_first_not_of(" \t"));
      value.erase(value.find_last_not_of(" \t") + 1);

      if (key == "script") {
        config.script_path = value;
      } else if (key == "verbose") {
        config.verbose = std::atoi(value.c_str());
      }
    }

    return config;
  }

  static std::optional<p01s0n_config> from_auto_discovery() {
    auto supported_extensions = p1ll::scripting::ScriptEngineFactory::get_supported_extensions();

    for (const auto& ext : supported_extensions) {
      std::string filename = "cure" + ext;
      if (std::filesystem::exists(filename)) {
        p01s0n_config config;
        config.source = config_source::auto_discovery;
        config.script_path = filename;
        return config;
      }
    }

    return std::nullopt;
  }

  static p01s0n_config discover() {
    if (auto config = from_config_file()) {
      return *config;
    }

    if (auto config = from_auto_discovery()) {
      return *config;
    }

    return from_environment();
  }

  const char* source_string() const {
    switch (source) {
    case config_source::config_file:
      return "config_file";
    case config_source::auto_discovery:
      return "auto_discovery";
    case config_source::environment:
      return "environment";
    default:
      return "none";
    }
  }
};

} // namespace p01s0n