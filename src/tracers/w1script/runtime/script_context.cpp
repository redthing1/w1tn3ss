#include "script_context.hpp"


namespace w1::tracers::script::runtime {

script_context::script_context(QBDI::VM* vm, const config& cfg)
    : cfg_(cfg), vm_(vm), logger_(redlog::get_logger("w1.script_context")) {
  if (!vm_) {
    logger_.err("vm is null in script context");
    return;
  }

  hook_manager_ = std::make_shared<w1::hooking::hook_manager>(vm_);
  gadget_executor_ = std::make_shared<w1tn3ss::gadget::gadget_executor>(vm_);
  symbol_resolver_ = std::make_unique<w1::symbols::symbol_resolver>();
  symbol_lookup_ = std::make_unique<w1::symbols::symbol_lookup>();
  output_ = std::make_unique<output_state>();

  auto context = p1ll::context::create_dynamic();
  p1ll_context_ = std::shared_ptr<p1ll::context>(std::move(context));

  refresh_modules();
}

bool script_context::refresh_modules() {
  auto modules = module_scanner_.scan_executable_modules();
  module_index_.rebuild_from_modules(std::move(modules));
  if (symbol_lookup_) {
    symbol_lookup_->initialize(module_index_);
  }
  logger_.inf("module index refreshed", redlog::field("modules", module_index_.size()));
  return module_index_.size() > 0;
}

void script_context::shutdown() {
  if (output_) {
    output_->close();
  }

  if (hook_manager_) {
    hook_manager_->remove_all_hooks();
  }
}

} // namespace w1::tracers::script::runtime
