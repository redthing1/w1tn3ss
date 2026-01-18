#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <QBDI.h>

#include "w1instrument/core/event_router.hpp"
#include "w1instrument/core/instrumentation_policy.hpp"
#include "w1instrument/core/vm_controller.hpp"
#include "w1runtime/module_registry.hpp"
#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/tracer.hpp"
#include "w1runtime/memory_reader.hpp"

namespace w1 {

using instrumentation_policy = core::instrumentation_policy;

struct trace_session_config {
  instrumentation_policy instrumentation{};
  uint64_t thread_id = 0;
  std::string thread_name = "main";
  QBDI::Options vm_options = QBDI::Options::NO_OPT;
};

template <tracer tracer_t> class trace_session {
public:
  explicit trace_session(trace_session_config config, tracer_t tracer_instance)
      : config_(std::move(config)), tracer_(std::move(tracer_instance)), vm_controller_(), module_registry_(),
        memory_reader_(vm_controller_.vm(), module_registry_),
        context_(config_.thread_id, vm_controller_.vm(), &module_registry_, &memory_reader_),
        event_router_(vm_controller_.vm()) {
    apply_options();
  }

  trace_session(trace_session_config config, tracer_t tracer_instance, QBDI::VM* borrowed_vm)
      : config_(std::move(config)), tracer_(std::move(tracer_instance)), vm_controller_(borrowed_vm),
        module_registry_(), memory_reader_(vm_controller_.vm(), module_registry_),
        context_(config_.thread_id, vm_controller_.vm(), &module_registry_, &memory_reader_),
        event_router_(vm_controller_.vm()) {
    apply_options();
  }

  template <typename... Args>
  explicit trace_session(trace_session_config config, std::in_place_t, Args&&... args)
      : config_(std::move(config)), tracer_(std::forward<Args>(args)...), vm_controller_(), module_registry_(),
        memory_reader_(vm_controller_.vm(), module_registry_),
        context_(config_.thread_id, vm_controller_.vm(), &module_registry_, &memory_reader_),
        event_router_(vm_controller_.vm()) {
    apply_options();
  }

  template <typename... Args>
  trace_session(trace_session_config config, QBDI::VM* borrowed_vm, std::in_place_t, Args&&... args)
      : config_(std::move(config)), tracer_(std::forward<Args>(args)...), vm_controller_(borrowed_vm),
        module_registry_(), memory_reader_(vm_controller_.vm(), module_registry_),
        context_(config_.thread_id, vm_controller_.vm(), &module_registry_, &memory_reader_),
        event_router_(vm_controller_.vm()) {
    apply_options();
  }

  trace_session(const trace_session&) = delete;
  trace_session& operator=(const trace_session&) = delete;
  trace_session(trace_session&&) = delete;
  trace_session& operator=(trace_session&&) = delete;

  ~trace_session() { shutdown(); }

  tracer_t& tracer() { return tracer_; }
  const tracer_t& tracer() const { return tracer_; }

  bool initialize() {
    if (initialized_) {
      return true;
    }

    validate_tracer<tracer_t>();

    QBDI::VM* vm = vm_controller_.vm();
    if (!vm) {
      return false;
    }

    module_registry_.refresh();

    event_mask mask = tracer_t::requested_events();
    if (!event_router_.configure(mask, tracer_, context_)) {
      return false;
    }
    if (!event_router_.enable_memory_recording()) {
      return false;
    }

    if (event_mask_has(mask, event_kind::thread_start)) {
      if constexpr (has_on_thread_start<tracer_t>) {
        thread_event event{};
        event.thread_id = context_.thread_id();
        event.name = config_.thread_name.c_str();
        tracer_.on_thread_start(context_, event);
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

    vm->removeAllInstrumentedRanges();
    module_registry_.refresh();

    auto modules = module_registry_.list_modules();
    size_t added = 0;

    for (const auto& module : modules) {
      if (!config_.instrumentation.should_instrument(module)) {
        continue;
      }

      for (const auto& range : module.exec_ranges) {
        if (range.end <= range.start) {
          continue;
        }
        vm->addInstrumentedRange(range.start, range.end);
        ++added;
      }
    }

    if (!event_router_.enable_memory_recording()) {
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

    return vm->run(static_cast<QBDI::rword>(start), static_cast<QBDI::rword>(stop));
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
        event.thread_id = context_.thread_id();
        event.name = config_.thread_name.c_str();
        tracer_.on_thread_stop(context_, event);
      }
    }

    if (clear_callbacks) {
      event_router_.clear();
    } else {
      event_router_.detach();
    }
    initialized_ = false;
    instrumented_ = false;
  }

private:
  void apply_options() {
    QBDI::VM* vm = vm_controller_.vm();
    if (vm && config_.vm_options != QBDI::Options::NO_OPT) {
      vm->setOptions(config_.vm_options);
    }
  }

  trace_session_config config_{};
  tracer_t tracer_{};
  core::vm_controller vm_controller_{};
  runtime::module_registry module_registry_{};
  util::memory_reader memory_reader_;
  trace_context context_;
  core::event_router<tracer_t> event_router_;
  bool initialized_ = false;
  bool instrumented_ = false;
};

} // namespace w1
