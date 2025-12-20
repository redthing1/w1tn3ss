#pragma once

#include <string>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/engine/instrumentation_config.hpp>

namespace w1xfer {

struct transfer_capture_config {
  bool registers = true;
  bool stack = true;
};

struct transfer_enrich_config {
  bool modules = true;
  bool symbols = true;
  bool analyze_apis = false;
};

struct transfer_output_config {
  std::string path = "";
  bool emit_metadata = true;
};

struct transfer_config : public w1::instrumentation_config {
  int verbose = 0;
  transfer_capture_config capture;
  transfer_enrich_config enrich;
  transfer_output_config output;

  static transfer_config from_environment() {
    w1::util::env_config loader("W1XFER_");

    transfer_config config;
    config.include_system_modules = loader.get<bool>("INCLUDE_SYSTEM", false);
    config.verbose = loader.get<int>("VERBOSE", 0);

    config.capture.registers = loader.get<bool>("CAPTURE_REGISTERS", true);
    config.capture.stack = loader.get<bool>("CAPTURE_STACK", true);

    config.enrich.modules = loader.get<bool>("ENRICH_MODULES", true);
    config.enrich.symbols = loader.get<bool>("ENRICH_SYMBOLS", true);
    config.enrich.analyze_apis = loader.get<bool>("ANALYZE_APIS", false);

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
