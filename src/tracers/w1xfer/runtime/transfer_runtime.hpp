#pragma once

#include <memory>
#include <utility>

#include "config/transfer_config.hpp"
#include "engine/transfer_engine.hpp"
#include "thread/transfer_tracer.hpp"
#include "w1instrument/tracer/runtime.hpp"
#include "w1runtime/thread_catalog.hpp"

namespace w1xfer {

struct transfer_traits {
  using tracer_type = transfer_tracer;
  using process_config = typename w1::instrument::process_session<tracer_type>::config;

  static process_config make_process_config(const transfer_config& config, bool owns_observer) {
    process_config session_config{};
    session_config.instrumentation = config.common.instrumentation;
    session_config.attach_new_threads =
        config.threads == w1::instrument::config::thread_attach_policy::auto_attach;
    session_config.refresh_on_module_events = true;
    session_config.owns_observer = owns_observer;
    return session_config;
  }

  static tracer_type make_tracer(
      std::shared_ptr<transfer_engine> engine, const transfer_config& config, const w1::runtime::thread_info& info
  ) {
    return tracer_type(std::move(engine), config, info);
  }

  static void configure_engine(transfer_engine& engine, w1::runtime::module_catalog& modules) {
    engine.configure(modules);
  }

  static bool export_output(transfer_engine& engine) { return engine.export_output(); }
};

struct transfer_runtime {
  using session_type =
      w1::instrument::tracer_runtime<transfer_engine, transfer_tracer, transfer_config, transfer_traits>;

  std::unique_ptr<session_type> session;
};

inline transfer_runtime make_transfer_runtime(transfer_config config) {
  transfer_runtime runtime;
  runtime.session = std::make_unique<transfer_runtime::session_type>(std::move(config));
  return runtime;
}

} // namespace w1xfer
