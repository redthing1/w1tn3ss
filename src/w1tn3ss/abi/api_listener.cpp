#include "api_listener.hpp"

#include <utility>

namespace w1::abi {

api_listener::api_listener(const analyzer_config& config) : dispatcher_(config) {}

void api_listener::initialize(const util::module_range_index& index) { dispatcher_.initialize(index); }

std::optional<api_event> api_listener::analyze_call(const api_context& ctx) { return dispatcher_.analyze_call(ctx); }

std::optional<api_event> api_listener::analyze_return(const api_context& ctx) {
  return dispatcher_.analyze_return(ctx);
}

void api_listener::process_call(const api_context& ctx) { dispatcher_.process_call(ctx); }

void api_listener::process_return(const api_context& ctx) { dispatcher_.process_return(ctx); }

void api_listener::register_symbol_callback(
    const std::string& module, const std::string& symbol, api_callback_fn callback
) {
  dispatcher_.register_symbol_callback(module, symbol, std::move(callback));
}

void api_listener::register_module_callback(const std::string& module, api_callback_fn callback) {
  dispatcher_.register_module_callback(module, std::move(callback));
}

void api_listener::register_category_callback(api_info::category category, api_callback_fn callback) {
  dispatcher_.register_category_callback(category, std::move(callback));
}

void api_listener::unregister_symbol_callback(const std::string& module, const std::string& symbol) {
  dispatcher_.unregister_symbol_callback(module, symbol);
}

void api_listener::unregister_module_callback(const std::string& module) { dispatcher_.unregister_module_callback(module); }

void api_listener::unregister_category_callback(api_info::category category) {
  dispatcher_.unregister_category_callback(category);
}

void api_listener::clear_all_callbacks() { dispatcher_.clear_all_callbacks(); }

api_analyzer& api_listener::get_analyzer() { return dispatcher_.get_analyzer(); }

const api_knowledge_db& api_listener::get_api_db() const { return dispatcher_.get_api_db(); }

api_listener::stats api_listener::get_stats() const { return dispatcher_.get_stats(); }

} // namespace w1::abi
