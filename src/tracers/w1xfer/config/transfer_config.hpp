#pragma once

#include <cstddef>
#include <string>

#include "w1instrument/config/tracer_common_config.hpp"
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
  w1::instrument::config::tracer_common_config common{};
  w1::instrument::config::thread_attach_policy threads = w1::instrument::config::thread_attach_policy::auto_attach;
  transfer_capture_config capture;
  transfer_enrich_config enrich;
  transfer_output_config output;

  static transfer_config from_environment() {
    w1::util::env_config loader("W1XFER");

    transfer_config config;
    config.common = w1::instrument::config::load_common(loader);
    config.threads = w1::instrument::config::load_thread_attach_policy(
        loader, w1::instrument::config::thread_attach_policy::auto_attach
    );

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
