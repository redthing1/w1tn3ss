#include "rewind_session.hpp"

#include <utility>
#include <vector>

namespace w1rewind {
namespace threading = w1::runtime::threading;

rewind_session::rewind_session(
    rewind_config config, w1::rewind::trace_sink_ptr sink, w1::rewind::trace_validator_ptr validator, uint64_t thread_id,
    std::string thread_name, redlog::logger log
)
    : config_(std::move(config)),
      sink_(std::move(sink)),
      validator_(std::move(validator)),
      thread_id_(thread_id),
      thread_name_(std::move(thread_name)),
      log_(std::move(log)) {}

bool rewind_session::initialize_main(QBDI::VMInstanceRef vm_ref) {
  vm_ = static_cast<QBDI::VM*>(vm_ref);
  owned_vm_.reset();

  if (!vm_) {
    log_.err("main thread vm is null", redlog::field("thread_id", thread_id_));
    return false;
  }

  if (!sink_) {
    log_.err("trace sink unavailable", redlog::field("thread_id", thread_id_));
    return false;
  }

  tracer_ = std::make_unique<rewind_tracer>(config_, sink_, validator_, thread_id_, thread_name_, log_);
  return setup_tracer();
}

bool rewind_session::initialize_worker() {
  try {
    owned_vm_ = std::make_unique<QBDI::VM>();
    vm_ = owned_vm_.get();
  } catch (...) {
    log_.err("failed to allocate worker vm", redlog::field("thread_id", thread_id_));
    vm_ = nullptr;
    owned_vm_.reset();
    return false;
  }

  if (!sink_) {
    log_.err("trace sink unavailable", redlog::field("thread_id", thread_id_));
    return false;
  }

  tracer_ = std::make_unique<rewind_tracer>(config_, sink_, validator_, thread_id_, thread_name_, log_);
  return setup_tracer();
}

threading::thread_result_t rewind_session::run_worker(threading::thread_start_fn start_routine, void* arg) {
  if (!start_routine) {
    return threading::thread_result_t{};
  }

  if (!vm_ || !tracer_) {
    return start_routine(arg);
  }

  QBDI::rword retval = 0;
  std::vector<QBDI::rword> args = {reinterpret_cast<QBDI::rword>(arg)};

  if (vm_->switchStackAndCall(&retval, reinterpret_cast<QBDI::rword>(start_routine), args)) {
#if defined(_WIN32)
    return static_cast<threading::thread_result_t>(retval);
#else
    return reinterpret_cast<threading::thread_result_t>(retval);
#endif
  }

  log_.wrn("switchStackAndCall failed; executing start routine directly", redlog::field("thread_id", thread_id_));
  return start_routine(arg);
}

void rewind_session::shutdown() {
  if (tracer_) {
    tracer_->shutdown();
  }

  tracer_.reset();
  vm_ = nullptr;
  owned_vm_.reset();
}

bool rewind_session::setup_tracer() {
  if (!vm_ || !tracer_) {
    return false;
  }

  if (!apply_instrumentation()) {
    log_.err("instrumentation setup failed", redlog::field("thread_id", thread_id_));
    return false;
  }

  if (!tracer_->initialize(*vm_)) {
    log_.err("tracer initialization failed", redlog::field("thread_id", thread_id_));
    return false;
  }

  return true;
}

bool rewind_session::apply_instrumentation() {
  if (!vm_) {
    return false;
  }

  w1::instrumentation_manager manager(config_);
  if (!manager.apply_instrumentation(vm_)) {
    log_.err("apply_instrumentation failed", redlog::field("thread_id", thread_id_));
    return false;
  }

  return true;
}

rewind_session_factory::rewind_session_factory(
    rewind_config config, w1::rewind::trace_sink_ptr sink, w1::rewind::trace_validator_ptr validator
)
    : config_(std::move(config)), sink_(std::move(sink)), validator_(std::move(validator)) {}

std::unique_ptr<w1::runtime::threading::thread_tracer_session> rewind_session_factory::create_for_main_thread(
    uint64_t thread_id, std::string_view thread_name, redlog::logger log
) {
  return std::make_unique<rewind_session>(config_, sink_, validator_, thread_id, std::string(thread_name), log);
}

std::unique_ptr<w1::runtime::threading::thread_tracer_session> rewind_session_factory::create_for_worker_thread(
    uint64_t thread_id, std::string_view thread_name, redlog::logger log
) {
  return std::make_unique<rewind_session>(config_, sink_, validator_, thread_id, std::string(thread_name), log);
}

} // namespace w1rewind
