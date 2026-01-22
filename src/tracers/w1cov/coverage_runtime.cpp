#include "coverage_runtime.hpp"

namespace w1cov {

coverage_runtime::coverage_runtime(coverage_config config)
    : engine_(std::make_shared<coverage_engine>(config)), config_(std::move(config)) {
  observer_.modules().refresh();
  engine_->configure(observer_.modules());
}

bool coverage_runtime::run_main(QBDI::VM* vm, uint64_t start, uint64_t stop, std::string name) {
  reset_instrumentors();

  if (config_.inst_trace) {
    inst_instrumentor::config process_config{};
    process_config.instrumentation = config_.instrumentation;
    process_config.attach_new_threads = true;
    process_config.refresh_on_module_events = true;
    process_config.owns_observer = true;

    inst_instrumentor_ = std::make_unique<inst_instrumentor>(
        observer_, process_config,
        [engine = engine_, flush = config_.thread_buffer_max](const w1::runtime::thread_info&) {
          return inst_recorder(engine, flush);
        }
    );

    return inst_instrumentor_->run_main(vm, start, stop, std::move(name));
  }

  block_instrumentor::config process_config{};
  process_config.instrumentation = config_.instrumentation;
  process_config.attach_new_threads = true;
  process_config.refresh_on_module_events = true;
  process_config.owns_observer = true;

  block_instrumentor_ = std::make_unique<block_instrumentor>(
      observer_, process_config,
      [engine = engine_, flush = config_.thread_buffer_max](const w1::runtime::thread_info&) {
        return block_recorder(engine, flush);
      }
  );

  return block_instrumentor_->run_main(vm, start, stop, std::move(name));
}

void coverage_runtime::stop() {
  reset_instrumentors();
}

bool coverage_runtime::export_coverage() {
  return engine_ ? engine_->export_coverage() : false;
}

void coverage_runtime::reset_instrumentors() {
  if (block_instrumentor_) {
    block_instrumentor_->stop();
    block_instrumentor_.reset();
  }
  if (inst_instrumentor_) {
    inst_instrumentor_->stop();
    inst_instrumentor_.reset();
  }
}

} // namespace w1cov
