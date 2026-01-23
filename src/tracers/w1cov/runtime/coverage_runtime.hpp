#pragma once

#include <memory>
#include <utility>
#include <variant>

#include "config/coverage_config.hpp"
#include "engine/coverage_engine.hpp"
#include "thread/coverage_thread_tracer.hpp"
#include "w1instrument/tracer/runtime.hpp"

namespace w1cov {

template <coverage_mode mode> struct coverage_traits {
  using tracer_type = coverage_thread_tracer<mode>;
  using process_config = typename w1::instrument::process_session<tracer_type>::config;

  static process_config make_process_config(const coverage_config& config, bool owns_observer) {
    process_config tracer_config{};
    tracer_config.instrumentation = config.common.instrumentation;
    tracer_config.attach_new_threads =
        config.threads == w1::instrument::config::thread_attach_policy::auto_attach;
    tracer_config.refresh_on_module_events = true;
    tracer_config.owns_observer = owns_observer;
    return tracer_config;
  }

  static w1::instrument::thread_session_config make_thread_config(const coverage_config& config) {
    w1::instrument::thread_session_config session_config{};
    session_config.instrumentation = config.common.instrumentation;
    return session_config;
  }

  static tracer_type make_tracer(
      std::shared_ptr<coverage_engine> engine, const coverage_config& config, const w1::runtime::thread_info&
  ) {
    return tracer_type(std::move(engine), config.buffer_flush_threshold);
  }

  static tracer_type make_tracer(std::shared_ptr<coverage_engine> engine, const coverage_config& config) {
    return tracer_type(std::move(engine), config.buffer_flush_threshold);
  }

  static void configure_engine(coverage_engine& engine, w1::runtime::module_catalog& modules) {
    engine.configure(modules);
  }

  static bool export_output(coverage_engine& engine) { return engine.export_coverage(); }
};

template <coverage_mode mode>
using coverage_process_runtime = w1::instrument::tracer_runtime<
    coverage_engine, coverage_thread_tracer<mode>, coverage_config, coverage_traits<mode>>;

template <coverage_mode mode>
using coverage_thread_runtime = w1::instrument::thread_runtime<
    coverage_engine, coverage_thread_tracer<mode>, coverage_config, coverage_traits<mode>>;

using coverage_process_runtime_any = std::variant<
    std::unique_ptr<coverage_process_runtime<coverage_mode::basic_block>>,
    std::unique_ptr<coverage_process_runtime<coverage_mode::instruction>>>;

using coverage_thread_runtime_any = std::variant<
    std::unique_ptr<coverage_thread_runtime<coverage_mode::basic_block>>,
    std::unique_ptr<coverage_thread_runtime<coverage_mode::instruction>>>;

inline coverage_process_runtime_any make_process_runtime(coverage_config config) {
  if (config.mode == coverage_mode::instruction) {
    return coverage_process_runtime_any{
        std::make_unique<coverage_process_runtime<coverage_mode::instruction>>(std::move(config))
    };
  }
  return coverage_process_runtime_any{
      std::make_unique<coverage_process_runtime<coverage_mode::basic_block>>(std::move(config))
  };
}

inline coverage_thread_runtime_any make_thread_runtime(coverage_config config) {
  if (config.mode == coverage_mode::instruction) {
    return coverage_thread_runtime_any{
        std::make_unique<coverage_thread_runtime<coverage_mode::instruction>>(std::move(config))
    };
  }
  return coverage_thread_runtime_any{
      std::make_unique<coverage_thread_runtime<coverage_mode::basic_block>>(std::move(config))
  };
}

template <typename Variant, typename Fn> decltype(auto) with_runtime(Variant& runtime, Fn&& fn) {
  return std::visit([&](auto& ptr) -> decltype(auto) { return fn(*ptr); }, runtime);
}

template <typename Variant, typename Fn> decltype(auto) with_runtime(const Variant& runtime, Fn&& fn) {
  return std::visit([&](const auto& ptr) -> decltype(auto) { return fn(*ptr); }, runtime);
}

} // namespace w1cov
