#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <w1tn3ss/util/env_config.hpp>

namespace w1inst {

struct instruction_config {
  std::string output_file = "";
  std::string target_mnemonics;           // comma-separated list
  std::vector<std::string> mnemonic_list; // parsed list
  uint64_t max_entries = 1000000000;      // 1B default
  bool verbose = false;

  static instruction_config from_environment() {
    w1::util::env_config loader("W1INST_");

    instruction_config config;
    config.output_file = loader.get<std::string>("OUTPUT", "");
    config.target_mnemonics = loader.get<std::string>("MNEMONICS", "");

    if (config.target_mnemonics.empty()) {
      throw std::runtime_error("W1INST_MNEMONICS environment variable is required (comma-separated list)");
    }
    config.max_entries = loader.get<uint64_t>("MAX_ENTRIES", 1000000000);
    config.verbose = loader.get<bool>("VERBOSE", false);

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