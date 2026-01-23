#pragma once

#include <memory>
#include <utility>

#include "config/script_config.hpp"
#include "thread/script_tracer.hpp"
#include "w1instrument/tracer/runtime.hpp"

namespace w1::tracers::script {

class script_engine {
public:
  explicit script_engine(const script_config&) {}

  void configure(w1::runtime::module_catalog&) {}

  bool export_output() { return true; }
};

struct script_traits {
  using tracer_type = script_tracer;

  static w1::instrument::thread_session_config make_thread_config(const script_config& config) {
    w1::instrument::thread_session_config session_config{};
    session_config.instrumentation = config.common.instrumentation;
    return session_config;
  }

  static tracer_type make_tracer(std::shared_ptr<script_engine> engine, const script_config& config) {
    return tracer_type(std::move(engine), config);
  }

  static void configure_engine(script_engine& engine, w1::runtime::module_catalog& modules) {
    engine.configure(modules);
  }

  static bool export_output(script_engine& engine) { return engine.export_output(); }
};

struct script_runtime {
  using session_type = w1::instrument::thread_runtime<script_engine, script_tracer, script_config, script_traits>;

  std::unique_ptr<session_type> session;
};

inline script_runtime make_script_runtime(script_config config) {
  script_runtime runtime;
  runtime.session = std::make_unique<script_runtime::session_type>(std::move(config));
  return runtime;
}

} // namespace w1::tracers::script
