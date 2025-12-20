#include "script_tracer.hpp"

#include <redlog.hpp>

namespace w1::tracers::script {

script_tracer::script_tracer() : logger_(redlog::get_logger("w1.script_tracer")) {}

script_tracer::script_tracer(const config& cfg) : cfg_(cfg), logger_(redlog::get_logger("w1.script_tracer")) {}

script_tracer::~script_tracer() = default;

bool script_tracer::initialize(w1::tracer_engine<script_tracer>& engine) {
  if (!setup_configuration()) {
    return false;
  }

  vm_ = engine.get_vm();
  if (!vm_) {
    logger_.err("vm instance is null");
    return false;
  }

  context_ = std::make_unique<runtime::script_context>(vm_, cfg_);
  runtime_ = std::make_unique<runtime::lua_runtime>(*context_);

  if (!runtime_->initialize()) {
    logger_.err("lua runtime initialization failed");
    return false;
  }

  logger_.inf("initialization complete");
  return true;
}

bool script_tracer::setup_configuration() {
  if (cfg_.script_path.empty()) {
    cfg_ = config::from_environment();
  }

  if (!cfg_.is_valid()) {
    logger_.err("invalid configuration. W1SCRIPT_SCRIPT must be specified.");
    return false;
  }

  logger_.inf("initializing with lua support");
  logger_.inf("script path", redlog::field("path", cfg_.script_path));
  return true;
}

void script_tracer::shutdown() {
  if (runtime_) {
    runtime_->shutdown();
  }

  runtime_.reset();
  context_.reset();
}

QBDI::VMAction script_tracer::on_vm_start(QBDI::VMInstanceRef vm) {
  if (!runtime_) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_vm_start(vm);
}

} // namespace w1::tracers::script
