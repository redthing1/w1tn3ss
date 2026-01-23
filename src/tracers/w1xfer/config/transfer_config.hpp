#pragma once

#include <cstddef>
#include <string>

#include "w1instrument/core/instrumentation_policy.hpp"
#include "w1base/env_config.hpp"

namespace w1xfer {

struct transfer_capture_config {
  bool registers = true;
  bool stack = true;
};

struct transfer_enrich_config {
  bool modules = true;
  bool symbols = true;
  bool analyze_apis = false;
  size_t api_argument_count = 0;
};

struct transfer_output_config {
  std::string path = "";
  bool emit_metadata = true;
};

struct transfer_config {
  w1::core::instrumentation_policy instrumentation{};
  bool exclude_self = true;
  int verbose = 0;
  transfer_capture_config capture;
  transfer_enrich_config enrich;
  transfer_output_config output;

  static transfer_config from_environment() {
    w1::util::env_config loader("W1XFER");

    transfer_config config;
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
    config.verbose = loader.get<int>("VERBOSE", 0);

    config.capture.registers = loader.get<bool>("CAPTURE_REGISTERS", true);
    config.capture.stack = loader.get<bool>("CAPTURE_STACK", true);

    config.enrich.modules = loader.get<bool>("ENRICH_MODULES", true);
    config.enrich.symbols = loader.get<bool>("ENRICH_SYMBOLS", true);
    config.enrich.analyze_apis = loader.get<bool>("ANALYZE_APIS", false);
    config.enrich.api_argument_count = static_cast<size_t>(loader.get<uint64_t>("API_ARG_COUNT", 0));

    config.output.path = loader.get<std::string>("OUTPUT", "");
    config.output.emit_metadata = loader.get<bool>("EMIT_METADATA", true);

    if (config.enrich.analyze_apis) {
      config.enrich.modules = true;
      config.enrich.symbols = true;
    }

    return config;
  }
};

} // namespace w1xfer
