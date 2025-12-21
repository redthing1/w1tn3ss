#include "script_context.hpp"

#include <utility>

namespace w1::tracers::script::runtime {

script_context::script_context(
    QBDI::VM* vm, const script_config& config, w1::runtime::module_registry* modules,
    const w1::util::memory_reader* memory, uint64_t thread_id, std::string thread_name
)
    : config_(config), vm_(vm), modules_(modules), memory_(memory), thread_id_(thread_id),
      thread_name_(std::move(thread_name)), logger_(redlog::get_logger("w1script.context")) {
  symbol_lookup_.set_module_registry(modules_);
}

bool script_context::refresh_modules() {
  if (!modules_) {
    return false;
  }

  modules_->refresh();
  symbol_lookup_.clear_cache();
  return true;
}

void script_context::shutdown() { output_.close(); }

} // namespace w1::tracers::script::runtime
