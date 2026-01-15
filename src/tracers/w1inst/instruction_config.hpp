#pragma once

#include <cstddef>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "w1tn3ss/core/instrumentation_policy.hpp"
#include "w1tn3ss/util/env_config.hpp"

namespace w1inst {

struct instruction_config {
  w1::core::instrumentation_policy instrumentation{};
  bool exclude_self = true;
  std::string output_file = "";
  std::string target_mnemonics;
  std::vector<std::string> mnemonic_list;
  size_t buffer_size_bytes = 256 * 1024 * 1024;
  size_t flush_event_count = 1'000'000;
  size_t flush_byte_count = 0;
  int verbose = 0;

  static instruction_config from_environment() {
    w1::util::env_config loader("W1INST");

    instruction_config config;
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
    config.output_file = loader.get<std::string>("OUTPUT", "");
    config.target_mnemonics = loader.get<std::string>("MNEMONICS", "");
    config.buffer_size_bytes = static_cast<size_t>(loader.get<uint64_t>("BUFFER_SIZE", 256 * 1024 * 1024));
    config.flush_event_count = static_cast<size_t>(loader.get<uint64_t>("FLUSH_EVENTS", 1'000'000));
    config.flush_byte_count = static_cast<size_t>(loader.get<uint64_t>("FLUSH_BYTES", 0));
    config.verbose = loader.get<int>("VERBOSE", 0);

    config.parse_mnemonics();
    if (config.mnemonic_list.empty()) {
      throw std::runtime_error("W1INST_MNEMONICS is required (comma-separated list)");
    }

    return config;
  }

  void parse_mnemonics() {
    mnemonic_list.clear();
    std::string mnemonic;
    std::stringstream ss(target_mnemonics);

    while (std::getline(ss, mnemonic, ',')) {
      // trim whitespace
      mnemonic.erase(0, mnemonic.find_first_not_of(" \t"));
      mnemonic.erase(mnemonic.find_last_not_of(" \t") + 1);

      if (!mnemonic.empty()) {
        mnemonic_list.push_back(mnemonic);
      }
    }
  }
};

} // namespace w1inst
