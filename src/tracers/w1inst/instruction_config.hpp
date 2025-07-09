#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/engine/tracer_config_base.hpp>

namespace w1inst {

struct instruction_config : public w1::tracer_config_base {
  std::string output_file = "";
  std::string target_mnemonics;           // comma-separated list
  std::vector<std::string> mnemonic_list; // parsed list
  int verbose = 0;

  static instruction_config from_environment() {
    w1::util::env_config loader("W1INST_");

    instruction_config config;
    config.include_system_modules = loader.get<bool>("INCLUDE_SYSTEM", false);
    config.output_file = loader.get<std::string>("OUTPUT", "");
    config.target_mnemonics = loader.get<std::string>("MNEMONICS", "");

    if (config.target_mnemonics.empty()) {
      throw std::runtime_error("w1inst_mnemonics environment variable is required (comma-separated list)");
    }
    config.verbose = loader.get<int>("VERBOSE", 0);

    // parse comma-separated mnemonics
    config.parse_mnemonics();

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