#pragma once

#include <memory>
#include <utility>
#include <variant>

#include "config/rewind_config.hpp"
#include "engine/rewind_engine.hpp"
#include "thread/rewind_thread_tracer.hpp"
#include "w1instrument/tracer/runtime.hpp"

namespace w1rewind {

template <rewind_flow Mode, bool CaptureMemory>
struct rewind_traits {
  using tracer_type = rewind_thread_tracer<Mode, CaptureMemory>;
  using process_config = typename w1::instrument::process_session<tracer_type>::config;

  static process_config make_process_config(const rewind_config& config, bool owns_observer) {
    process_config tracer_config{};
    tracer_config.instrumentation = config.common.instrumentation;
    tracer_config.attach_new_threads =
        config.threads == w1::instrument::config::thread_attach_policy::auto_attach;
    tracer_config.refresh_on_module_events = true;
    tracer_config.owns_observer = owns_observer;
    return tracer_config;
  }

  static w1::instrument::thread_session_config make_thread_config(const rewind_config& config) {
    w1::instrument::thread_session_config session_config{};
    session_config.instrumentation = config.common.instrumentation;
    return session_config;
  }

  static tracer_type make_tracer(
      std::shared_ptr<rewind_engine> engine, const rewind_config& config, const w1::runtime::thread_info&
  ) {
    return tracer_type(std::move(engine), config);
  }

  static tracer_type make_tracer(std::shared_ptr<rewind_engine> engine, const rewind_config& config) {
    return tracer_type(std::move(engine), config);
  }

  static void configure_engine(rewind_engine& engine, w1::runtime::module_catalog& modules) {
    engine.configure(modules);
  }

  static bool export_output(rewind_engine& engine) { return engine.export_trace(); }

  static void configure_session(
      w1::instrument::process_session<tracer_type>& session, rewind_engine& engine, const rewind_config&
  ) {
    session.set_on_event([eng = &engine](const w1::runtime::process_event& event) { eng->on_process_event(event); });
  }
};

template <rewind_flow Mode, bool CaptureMemory>
using rewind_process_runtime =
    w1::instrument::tracer_runtime<rewind_engine, rewind_thread_tracer<Mode, CaptureMemory>, rewind_config,
                                   rewind_traits<Mode, CaptureMemory>>;

template <rewind_flow Mode, bool CaptureMemory>
using rewind_thread_runtime =
    w1::instrument::thread_runtime<rewind_engine, rewind_thread_tracer<Mode, CaptureMemory>, rewind_config,
                                   rewind_traits<Mode, CaptureMemory>>;

using rewind_process_runtime_any = std::variant<
    std::unique_ptr<rewind_process_runtime<rewind_flow::instruction, true>>,
    std::unique_ptr<rewind_process_runtime<rewind_flow::instruction, false>>,
    std::unique_ptr<rewind_process_runtime<rewind_flow::block, false>>>;

using rewind_thread_runtime_any = std::variant<
    std::unique_ptr<rewind_thread_runtime<rewind_flow::instruction, true>>,
    std::unique_ptr<rewind_thread_runtime<rewind_flow::instruction, false>>,
    std::unique_ptr<rewind_thread_runtime<rewind_flow::block, false>>>;

inline rewind_process_runtime_any make_process_runtime(rewind_config config) {
  if (config.flow.mode == rewind_config::flow_options::flow_mode::instruction) {
    if (config.memory.access != rewind_config::memory_access::none) {
      return rewind_process_runtime_any{
          std::make_unique<rewind_process_runtime<rewind_flow::instruction, true>>(std::move(config))
      };
    }
    return rewind_process_runtime_any{
        std::make_unique<rewind_process_runtime<rewind_flow::instruction, false>>(std::move(config))
    };
  }
  return rewind_process_runtime_any{
      std::make_unique<rewind_process_runtime<rewind_flow::block, false>>(std::move(config))
  };
}

inline rewind_thread_runtime_any make_thread_runtime(rewind_config config) {
  if (config.flow.mode == rewind_config::flow_options::flow_mode::instruction) {
    if (config.memory.access != rewind_config::memory_access::none) {
      return rewind_thread_runtime_any{
          std::make_unique<rewind_thread_runtime<rewind_flow::instruction, true>>(std::move(config))
      };
    }
    return rewind_thread_runtime_any{
        std::make_unique<rewind_thread_runtime<rewind_flow::instruction, false>>(std::move(config))
    };
  }
  return rewind_thread_runtime_any{
      std::make_unique<rewind_thread_runtime<rewind_flow::block, false>>(std::move(config))
  };
}

template <typename Variant, typename Fn> decltype(auto) with_runtime(Variant& runtime, Fn&& fn) {
  return std::visit([&](auto& ptr) -> decltype(auto) { return fn(*ptr); }, runtime);
}

template <typename Variant, typename Fn> decltype(auto) with_runtime(const Variant& runtime, Fn&& fn) {
  return std::visit([&](const auto& ptr) -> decltype(auto) { return fn(*ptr); }, runtime);
}

} // namespace w1rewind
