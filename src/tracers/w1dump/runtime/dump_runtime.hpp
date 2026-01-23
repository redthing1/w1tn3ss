#pragma once

#include <memory>
#include <utility>

#include "config/dump_config.hpp"
#include "engine/dump_engine.hpp"
#include "instrument/dump_recorder.hpp"
#include "w1instrument/tracer/runtime.hpp"

namespace w1dump {

struct dump_traits {
  using tracer_type = dump_recorder;

  static w1::instrument::thread_session_config make_thread_config(const dump_config& config) {
    w1::instrument::thread_session_config session_config{};
    session_config.instrumentation = config.instrumentation;
    return session_config;
  }

  static tracer_type make_tracer(std::shared_ptr<dump_engine> engine, const dump_config&) {
    return tracer_type(std::move(engine));
  }

  static void configure_engine(dump_engine&, w1::runtime::module_catalog&) {}

  static bool export_output(dump_engine& engine) { return engine.dump_completed(); }
};

struct dump_runtime {
  using session_type = w1::instrument::thread_runtime<dump_engine, dump_recorder, dump_config, dump_traits>;

  std::unique_ptr<session_type> session;
};

inline dump_runtime make_dump_runtime(dump_config config) {
  dump_runtime runtime;
  runtime.session = std::make_unique<dump_runtime::session_type>(std::move(config));
  return runtime;
}

} // namespace w1dump
