#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <QBDI.h>
#include <redlog.hpp>

#include "w1base/thread_utils.hpp"
#include "w1instrument/core/instrumentation_policy.hpp"
#include "w1instrument/core/vm_controller.hpp"
#include "w1instrument/trace/event_dispatcher.hpp"
#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/tracer.hpp"
#include "w1runtime/memory_reader.hpp"
#include "w1runtime/module_catalog.hpp"

namespace w1::instrument {

struct thread_session_config {
  core::instrumentation_policy instrumentation{};
  uint64_t thread_id = 0;
  std::string thread_name = "thread";
  QBDI::Options vm_options = QBDI::Options::NO_OPT;
  runtime::module_catalog* shared_modules = nullptr;
};

// Per-thread QBDI session wired to a tracer instance.
template <tracer tracer_t> class thread_session {
public:
  explicit thread_session(thread_session_config config, tracer_t tracer_instance)
      : config_(std::move(config)), tracer_(std::move(tracer_instance)), vm_controller_(),
        dispatcher_(vm_controller_.vm()) {
    init_shared_state();
    apply_options();
  }

  thread_session(thread_session_config config, tracer_t tracer_instance, QBDI::VM* borrowed_vm)
      : config_(std::move(config)), tracer_(std::move(tracer_instance)), vm_controller_(borrowed_vm),
        dispatcher_(vm_controller_.vm()) {
    init_shared_state();
    apply_options();
  }

  template <typename... Args>
  explicit thread_session(thread_session_config config, std::in_place_t, Args&&... args)
      : config_(std::move(config)), tracer_(std::forward<Args>(args)...), vm_controller_(),
        dispatcher_(vm_controller_.vm()) {
    init_shared_state();
    apply_options();
  }

  template <typename... Args>
  thread_session(thread_session_config config, QBDI::VM* borrowed_vm, std::in_place_t, Args&&... args)
      : config_(std::move(config)), tracer_(std::forward<Args>(args)...), vm_controller_(borrowed_vm),
        dispatcher_(vm_controller_.vm()) {
    init_shared_state();
    apply_options();
  }

  thread_session(const thread_session&) = delete;
  thread_session& operator=(const thread_session&) = delete;
  thread_session(thread_session&&) = delete;
  thread_session& operator=(thread_session&&) = delete;

  ~thread_session() { shutdown(); }

  tracer_t& tracer() { return tracer_; }
  const tracer_t& tracer() const { return tracer_; }

  trace_context& context() { return *context_; }
  const trace_context& context() const { return *context_; }

  void request_refresh() { refresh_requested_.store(true, std::memory_order_release); }

  bool initialize() {
    if (initialized_) {
      return true;
    }

    validate_tracer<tracer_t>();

    QBDI::VM* vm = vm_controller_.vm();
    if (!vm) {
      return false;
    }

    if (owned_modules_) {
      modules_->refresh();
    }

    event_mask mask = tracer_t::requested_events();
    if (!dispatcher_.bind(mask, tracer_, *context_)) {
      return false;
    }

    if (event_mask_has(mask, event_kind::thread_start)) {
      if constexpr (has_on_thread_start<tracer_t>) {
        thread_event event{};
        event.thread_id = context_->thread_id();
        event.name = config_.thread_name.c_str();
        tracer_.on_thread_start(*context_, event);
      }
    }

    if (refresh_callback_id_ == QBDI::INVALID_EVENTID) {
      refresh_callback_id_ = vm->addCodeCB(
          QBDI::PREINST,
          [](QBDI::VMInstanceRef, QBDI::GPRState*, QBDI::FPRState*, void* data) -> QBDI::VMAction {
            auto* session = static_cast<thread_session*>(data);
            if (session->refresh_requested_.exchange(false, std::memory_order_acq_rel)) {
              session->refresh_instrumentation();
            }
            return QBDI::VMAction::CONTINUE;
          },
          this
      );
      if (refresh_callback_id_ == QBDI::INVALID_EVENTID) {
        return false;
      }
    }

    initialized_ = true;
    return true;
  }

  bool instrument() {
    if (!initialize()) {
      return false;
    }

    if (instrumented_) {
      return true;
    }

    QBDI::VM* vm = vm_controller_.vm();
    if (!vm) {
      return false;
    }

    size_t added = refresh_instrumentation();
    if (!dispatcher_.ensure_memory_recording()) {
      return false;
    }

    instrumented_ = added > 0;
    return instrumented_;
  }

  bool run(uint64_t start, uint64_t stop) {
    if (!instrument()) {
      return false;
    }

    QBDI::VM* vm = vm_controller_.vm();
    if (!vm) {
      return false;
    }

    bool ok = vm->run(static_cast<QBDI::rword>(start), static_cast<QBDI::rword>(stop));
    if (!ok) {
      auto log = redlog::get_logger("w1instrument.thread_session");
      log.wrn(
          "qbdi run returned false", redlog::field("thread_id", config_.thread_id), redlog::field("start", start),
          redlog::field("stop", stop), redlog::field("include_filters", config_.instrumentation.include_modules.size()),
          redlog::field("exclude_filters", config_.instrumentation.exclude_modules.size()),
          redlog::field("use_default_excludes", config_.instrumentation.use_default_excludes),
          redlog::field("include_unnamed", config_.instrumentation.include_unnamed_modules),
          redlog::field("system_policy", static_cast<int>(config_.instrumentation.system_policy))
      );
    }
    return ok;
  }

  bool call(uint64_t function_ptr, const std::vector<uint64_t>& args, uint64_t* result) {
    if (!instrument()) {
      return false;
    }

    QBDI::VM* vm = vm_controller_.vm();
    if (!vm) {
      return false;
    }

    std::vector<QBDI::rword> qbdi_args;
    qbdi_args.reserve(args.size());
    for (uint64_t arg : args) {
      qbdi_args.push_back(static_cast<QBDI::rword>(arg));
    }

    QBDI::rword retval = 0;
    bool success = vm->switchStackAndCall(&retval, static_cast<QBDI::rword>(function_ptr), qbdi_args);
    if (success && result) {
      *result = static_cast<uint64_t>(retval);
    }

    return success;
  }

  void shutdown(bool clear_callbacks = true) {
    if (!initialized_) {
      return;
    }

    event_mask mask = tracer_t::requested_events();
    if (event_mask_has(mask, event_kind::thread_stop)) {
      if constexpr (has_on_thread_stop<tracer_t>) {
        thread_event event{};
        event.thread_id = context_->thread_id();
        event.name = config_.thread_name.c_str();
        tracer_.on_thread_stop(*context_, event);
      }
    }

    if (clear_callbacks) {
      dispatcher_.clear();
      if (refresh_callback_id_ != QBDI::INVALID_EVENTID) {
        vm_controller_.vm()->deleteInstrumentation(refresh_callback_id_);
      }
    } else {
      dispatcher_.detach();
    }

    refresh_callback_id_ = QBDI::INVALID_EVENTID;
    initialized_ = false;
    instrumented_ = false;
  }

private:
  void init_shared_state() {
    if (config_.thread_id == 0) {
      config_.thread_id = w1::util::current_thread_id();
    }

    if (config_.shared_modules) {
      modules_ = config_.shared_modules;
    } else {
      owned_modules_ = std::make_unique<runtime::module_catalog>();
      modules_ = owned_modules_.get();
    }

    memory_reader_ = std::make_unique<util::memory_reader>(vm_controller_.vm(), *modules_);
    context_ = std::make_unique<trace_context>(config_.thread_id, vm_controller_.vm(), modules_, memory_reader_.get());
  }

  size_t refresh_instrumentation() {
    QBDI::VM* vm = vm_controller_.vm();
    if (!vm || !modules_) {
      return 0;
    }

    if (owned_modules_) {
      modules_->refresh();
    }

    vm->removeAllInstrumentedRanges();

    auto modules = modules_->list_modules();
    size_t added = 0;
    size_t eligible_modules = 0;
    size_t eligible_ranges = 0;

    for (const auto& module : modules) {
      if (!config_.instrumentation.should_instrument(module)) {
        continue;
      }
      ++eligible_modules;

      for (const auto& range : module.exec_ranges) {
        if (range.end <= range.start) {
          continue;
        }
        vm->addInstrumentedRange(range.start, range.end);
        ++added;
        ++eligible_ranges;
      }
    }

    vm->clearAllCache();

    instrumented_ = added > 0;
    if (!instrumented_) {
      auto log = redlog::get_logger("w1instrument.thread_session");
      log.wrn(
          "no instrumented ranges; tracer may exit immediately", redlog::field("thread_id", config_.thread_id),
          redlog::field("module_count", modules.size()), redlog::field("eligible_modules", eligible_modules),
          redlog::field("eligible_ranges", eligible_ranges),
          redlog::field("include_filters", config_.instrumentation.include_modules.size()),
          redlog::field("exclude_filters", config_.instrumentation.exclude_modules.size()),
          redlog::field("use_default_excludes", config_.instrumentation.use_default_excludes),
          redlog::field("include_unnamed", config_.instrumentation.include_unnamed_modules),
          redlog::field("system_policy", static_cast<int>(config_.instrumentation.system_policy))
      );
    }
    return added;
  }

  void apply_options() {
    QBDI::VM* vm = vm_controller_.vm();
    if (vm && config_.vm_options != QBDI::Options::NO_OPT) {
      vm->setOptions(config_.vm_options);
    }
  }

  thread_session_config config_{};
  tracer_t tracer_{};
  core::vm_controller vm_controller_{};
  std::unique_ptr<runtime::module_catalog> owned_modules_{};
  runtime::module_catalog* modules_ = nullptr;
  std::unique_ptr<util::memory_reader> memory_reader_{};
  std::unique_ptr<trace_context> context_{};
  event_dispatcher<tracer_t> dispatcher_;
  bool initialized_ = false;
  bool instrumented_ = false;
  std::atomic<bool> refresh_requested_{false};
  uint32_t refresh_callback_id_ = QBDI::INVALID_EVENTID;
};

} // namespace w1::instrument
