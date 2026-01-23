#pragma once

#include <memory>
#include <utility>

#include "config/transfer_config.hpp"
#include "engine/transfer_engine.hpp"
#include "thread/transfer_tracer.hpp"
#include "w1instrument/tracer/runtime.hpp"

namespace w1xfer {

struct transfer_traits {
  using tracer_type = transfer_tracer;

  static w1::instrument::thread_session_config make_thread_config(const transfer_config& config) {
    w1::instrument::thread_session_config session_config{};
    session_config.instrumentation = config.instrumentation;
    return session_config;
  }

  static tracer_type make_tracer(std::shared_ptr<transfer_engine> engine, const transfer_config& config) {
    return tracer_type(std::move(engine), config);
  }

  static void configure_engine(transfer_engine& engine, w1::runtime::module_catalog& modules) {
    engine.configure(modules);
  }

  static bool export_output(transfer_engine& engine) { return engine.export_output(); }
};

struct transfer_runtime {
  using session_type =
      w1::instrument::thread_runtime<transfer_engine, transfer_tracer, transfer_config, transfer_traits>;

  std::unique_ptr<session_type> session;
};

inline transfer_runtime make_transfer_runtime(transfer_config config) {
  transfer_runtime runtime;
  runtime.session = std::make_unique<transfer_runtime::session_type>(std::move(config));
  return runtime;
}

} // namespace w1xfer
