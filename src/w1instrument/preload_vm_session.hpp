#pragma once

#include <memory>

#include <QBDI.h>
#include <redlog.hpp>

#include "w1instrument/logging.hpp"
#include "w1instrument/preload_driver.hpp"
#include "w1instrument/self_exclude.hpp"
#include "w1instrument/tracer/vm_session.hpp"

namespace w1::instrument {

template <typename Derived, typename Config, typename Tracer>
struct vm_session_preload_policy {
  using config_type = Config;
  using runtime_type = w1::vm_session<Tracer>;

  static constexpr const char* kLoggerName = "w1.preload";
  static constexpr const char* kSessionLabel = "session";
  static constexpr const char* kRunFailedMessage = "session run failed";
  static constexpr const char* kThreadName = "main";

  static config_type load_config() {
    if constexpr (requires { Derived::load_config_override(); }) {
      return Derived::load_config_override();
    } else {
      return Config::from_environment();
    }
  }

  static void configure_logging(const config_type& config) {
    if constexpr (requires(const config_type& cfg) { Derived::configure_logging_override(cfg); }) {
      Derived::configure_logging_override(config);
    } else {
      w1::instrument::configure_redlog_verbosity(config.verbose);
    }
  }

  static bool should_exclude_self(const config_type& config) {
    if constexpr (requires(const config_type& cfg) { Derived::should_exclude_self_override(cfg); }) {
      return Derived::should_exclude_self_override(config);
    } else {
      return config.exclude_self;
    }
  }

  static void apply_self_excludes(config_type& config, const void* anchor) {
    if constexpr (requires(config_type& cfg, const void* ptr) { Derived::apply_self_excludes_override(cfg, ptr); }) {
      Derived::apply_self_excludes_override(config, anchor);
    } else {
      w1::util::append_self_excludes(config.instrumentation, anchor);
    }
  }

  static const char* logger_name() { return Derived::kLoggerName; }

  static const char* session_label() { return Derived::kSessionLabel; }

  static const char* run_failed_message() { return Derived::kRunFailedMessage; }

  static const char* thread_name() { return Derived::kThreadName; }

  static void configure_session(vm_session_config& session_config, const config_type& config) {
    if constexpr (requires(vm_session_config& cfg, const config_type& user_cfg) {
                    Derived::configure_session_override(cfg, user_cfg);
                  }) {
      Derived::configure_session_override(session_config, config);
    }
  }

  static std::unique_ptr<runtime_type> create_runtime(const config_type& config, QBDI::VMInstanceRef vm) {
    w1::vm_session_config session_config;
    session_config.instrumentation = config.instrumentation;
    session_config.thread_id = 1;
    session_config.thread_name = thread_name();

    configure_session(session_config, config);

    auto* vm_ptr = static_cast<QBDI::VM*>(vm);
    return std::make_unique<runtime_type>(session_config, vm_ptr, std::in_place, config);
  }

  static bool run(runtime_type& session, QBDI::VMInstanceRef, QBDI::rword start, QBDI::rword stop) {
    auto log = redlog::get_logger(logger_name());
    log.inf(
        "starting session", redlog::field("kind", session_label()),
        redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
        redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop))
    );
    return session.run(static_cast<uint64_t>(start), static_cast<uint64_t>(stop));
  }

  static void shutdown(runtime_type& session, int status, const config_type&) {
    auto log = redlog::get_logger(logger_name());
    log.inf("qbdipreload_on_exit called", redlog::field("status", status));
    session.shutdown(false);
    log.inf("qbdipreload_on_exit completed");
  }
};

template <typename Policy>
bool preload_run_or_log(
    preload_state<Policy>& state, const void* self_anchor, QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop
) {
  if (preload_run(state, self_anchor, vm, start, stop)) {
    return true;
  }

  auto log = redlog::get_logger(Policy::logger_name());
  log.err(Policy::run_failed_message());
  return false;
}

} // namespace w1::instrument
