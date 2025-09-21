#include "threadtest_session.hpp"

#include <vector>

namespace threadtest {
namespace threading = w1::runtime::threading;

threadtest_session::threadtest_session(
    threadtest_config config, uint64_t thread_id, std::string thread_name, redlog::logger log
)
    : config_(std::move(config)), thread_id_(thread_id), thread_name_(std::move(thread_name)), log_(std::move(log)) {}

bool threadtest_session::initialize_main(QBDI::VMInstanceRef vm_ref) {
  vm_ = static_cast<QBDI::VM*>(vm_ref);
  owned_vm_.reset();

  if (!vm_) {
    log_.err("main thread vm is null", redlog::field("thread_id", thread_id_));
    return false;
  }

  tracer_ = std::make_unique<threadtest_tracer>(config_, thread_id_, thread_name_, log_);
  return setup_tracer();
}

bool threadtest_session::initialize_worker() {
  try {
    owned_vm_ = std::make_unique<QBDI::VM>();
    vm_ = owned_vm_.get();
  } catch (...) {
    log_.err("failed to allocate worker vm", redlog::field("thread_id", thread_id_));
    vm_ = nullptr;
    owned_vm_.reset();
    return false;
  }

  tracer_ = std::make_unique<threadtest_tracer>(config_, thread_id_, thread_name_, log_);
  return setup_tracer();
}

threading::thread_result_t threadtest_session::run_worker(threading::thread_start_fn start_routine, void* arg) {
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

void threadtest_session::shutdown() {
  if (tracer_) {
    tracer_->shutdown();
  }

  tracer_.reset();
  vm_ = nullptr;
  owned_vm_.reset();
}

bool threadtest_session::setup_tracer() {
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

bool threadtest_session::apply_instrumentation() {
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

threadtest_session_factory::threadtest_session_factory(threadtest_config config) : config_(std::move(config)) {}

std::unique_ptr<w1::runtime::threading::thread_tracer_session> threadtest_session_factory::create_for_main_thread(
    uint64_t thread_id, std::string_view thread_name, redlog::logger log
) {
  return std::make_unique<threadtest_session>(config_, thread_id, std::string(thread_name), log);
}

std::unique_ptr<w1::runtime::threading::thread_tracer_session> threadtest_session_factory::create_for_worker_thread(
    uint64_t thread_id, std::string_view thread_name, redlog::logger log
) {
  return std::make_unique<threadtest_session>(config_, thread_id, std::string(thread_name), log);
}

} // namespace threadtest
