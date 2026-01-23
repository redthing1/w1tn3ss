#pragma once

#include <concepts>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <QBDI.h>

#include "w1base/thread_utils.hpp"
#include "w1instrument/process/process_session.hpp"
#include "w1instrument/trace/thread_session.hpp"
#include "w1runtime/module_catalog.hpp"
#include "w1runtime/process_observer.hpp"

namespace w1::instrument {

template <typename Traits, typename Engine, typename ThreadTracer, typename Config>
concept process_runtime_traits = requires(
    Engine& engine, const Config& config, const runtime::thread_info& info, bool owns_observer
) {
  { Traits::make_process_config(config, owns_observer) } ->
      std::same_as<typename process_session<ThreadTracer>::config>;
  { Traits::make_tracer(std::declval<std::shared_ptr<Engine>>(), config, info) } -> std::same_as<ThreadTracer>;
  { Traits::configure_engine(engine, std::declval<runtime::module_catalog&>()) } -> std::same_as<void>;
  { Traits::export_output(engine) } -> std::same_as<bool>;
};

template <typename Traits, typename Engine, typename ThreadTracer, typename Config>
concept thread_runtime_traits = requires(Engine& engine, const Config& config) {
  { Traits::make_thread_config(config) } -> std::same_as<thread_session_config>;
  { Traits::make_tracer(std::declval<std::shared_ptr<Engine>>(), config) } -> std::same_as<ThreadTracer>;
  { Traits::configure_engine(engine, std::declval<runtime::module_catalog&>()) } -> std::same_as<void>;
  { Traits::export_output(engine) } -> std::same_as<bool>;
};

template <typename Engine, typename ThreadTracer, typename Config, typename Traits>
requires process_runtime_traits<Traits, Engine, ThreadTracer, Config>
class tracer_runtime {
public:
  using session_type = process_session<ThreadTracer>;

  explicit tracer_runtime(Config config)
      : owned_observer_{}, observer_(&owned_observer_), config_(std::move(config)),
        engine_(std::make_shared<Engine>(config_)),
        session_(
            *observer_, Traits::make_process_config(config_, true),
            [engine = engine_, config_ptr = &config_](const runtime::thread_info& info) {
              return Traits::make_tracer(engine, *config_ptr, info);
            }
        ) {
    configure_engine();
  }

  tracer_runtime(Config config, runtime::process_observer& observer)
      : observer_(&observer), config_(std::move(config)), engine_(std::make_shared<Engine>(config_)),
        session_(
            observer, Traits::make_process_config(config_, false),
            [engine = engine_, config_ptr = &config_](const runtime::thread_info& info) {
              return Traits::make_tracer(engine, *config_ptr, info);
            }
        ) {
    configure_engine();
  }

  tracer_runtime(const tracer_runtime&) = delete;
  tracer_runtime& operator=(const tracer_runtime&) = delete;
  tracer_runtime(tracer_runtime&&) = delete;
  tracer_runtime& operator=(tracer_runtime&&) = delete;

  ~tracer_runtime() { stop(); }

  bool run_main(QBDI::VM* vm, uint64_t start, uint64_t stop, std::string name = "main") {
    configure_engine();
    return session_.run_main(vm, start, stop, std::move(name));
  }

  void stop() { session_.stop(); }

  bool export_output() { return engine_ ? Traits::export_output(*engine_) : false; }

  Engine& engine() const { return *engine_; }
  std::shared_ptr<Engine> engine_shared() const { return engine_; }
  session_type& session() { return session_; }
  const session_type& session() const { return session_; }
  runtime::process_observer& observer() { return *observer_; }
  const runtime::process_observer& observer() const { return *observer_; }

  void refresh_modules() {
    if (observer_) {
      observer_->modules().refresh();
    }
    session_.refresh_all();
  }

private:
  void configure_engine() {
    if (!observer_ || !engine_) {
      return;
    }
    observer_->modules().refresh();
    Traits::configure_engine(*engine_, observer_->modules());
  }

  runtime::process_observer owned_observer_{};
  runtime::process_observer* observer_ = nullptr;
  Config config_{};
  std::shared_ptr<Engine> engine_{};
  session_type session_;
};

template <typename Engine, typename ThreadTracer, typename Config, typename Traits>
requires thread_runtime_traits<Traits, Engine, ThreadTracer, Config>
class thread_runtime {
public:
  using session_type = thread_session<ThreadTracer>;

  explicit thread_runtime(Config config)
      : config_(std::move(config)), engine_(std::make_shared<Engine>(config_)) {
    configure_engine();
  }

  thread_runtime(const thread_runtime&) = delete;
  thread_runtime& operator=(const thread_runtime&) = delete;
  thread_runtime(thread_runtime&&) = delete;
  thread_runtime& operator=(thread_runtime&&) = delete;

  ~thread_runtime() { stop(); }

  bool run(QBDI::VM* vm, uint64_t start, uint64_t stop_address, std::string name = "thread") {
    configure_engine();

    thread_session_config session_config = Traits::make_thread_config(config_);
    if (session_config.thread_id == 0) {
      session_config.thread_id = w1::util::current_thread_id();
    }
    session_config.thread_name = name.empty() ? "thread" : std::move(name);
    session_config.shared_modules = &modules_;

    ThreadTracer tracer_instance = Traits::make_tracer(engine_, config_);
    if (vm) {
      session_ = std::make_unique<session_type>(session_config, std::move(tracer_instance), vm);
    } else {
      session_ = std::make_unique<session_type>(session_config, std::move(tracer_instance));
    }

    const bool ok = session_->run(start, stop_address);
    stop();
    return ok;
  }

  void stop() {
    if (session_) {
      session_->shutdown();
      session_.reset();
    }
  }

  bool export_output() {
    stop();
    return engine_ ? Traits::export_output(*engine_) : false;
  }

  Engine& engine() const { return *engine_; }
  std::shared_ptr<Engine> engine_shared() const { return engine_; }

private:
  void configure_engine() {
    modules_.refresh();
    if (engine_) {
      Traits::configure_engine(*engine_, modules_);
    }
  }

  Config config_{};
  std::shared_ptr<Engine> engine_{};
  runtime::module_catalog modules_{};
  std::unique_ptr<session_type> session_{};
};

} // namespace w1::instrument
