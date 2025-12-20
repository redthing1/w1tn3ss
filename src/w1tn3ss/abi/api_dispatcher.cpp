#include "api_dispatcher.hpp"

#include "api_event_builder.hpp"

namespace w1::abi {

api_dispatcher::api_dispatcher(const analyzer_config& config) : analyzer_(config), call_tracker_(api_call_tracker()) {}

void api_dispatcher::initialize(const util::module_range_index& index) { analyzer_.initialize(index); }

std::optional<api_event> api_dispatcher::analyze_call(const api_context& ctx) {
  stats_.total_calls_processed++;
  return analyze_call_internal(ctx);
}

std::optional<api_event> api_dispatcher::analyze_return(const api_context& ctx) {
  stats_.total_returns_processed++;

  auto call = call_tracker_.consume_return(ctx.target_address);
  if (!call) {
    return std::nullopt;
  }

  return analyze_return_internal(ctx, *call);
}

void api_dispatcher::process_call(const api_context& ctx) {
  stats_.total_calls_processed++;

  auto initial_category = api_info::category::UNKNOWN;
  if (auto api_info = analyzer_.get_api_db().lookup(ctx.symbol_name)) {
    initial_category = api_info->api_category;
  }

  if (!has_callbacks_for(ctx.module_name, ctx.symbol_name, initial_category)) {
    stats_.calls_filtered_out++;
    return;
  }

  if (auto event = analyze_call_internal(ctx)) {
    dispatch_event(*event);
  }
}

void api_dispatcher::process_return(const api_context& ctx) {
  stats_.total_returns_processed++;

  auto call = call_tracker_.consume_return(ctx.target_address);
  if (!call) {
    return;
  }

  if (!has_callbacks_for(call->module_name, call->symbol_name, call->category)) {
    stats_.returns_filtered_out++;
    return;
  }

  if (auto event = analyze_return_internal(ctx, *call)) {
    dispatch_event(*event);
  }
}

void api_dispatcher::register_symbol_callback(
    const std::string& module, const std::string& symbol, api_callback_fn callback
) {
  callbacks_.symbol_callbacks[make_filter_key(module, symbol)].push_back(std::move(callback));
}

void api_dispatcher::register_module_callback(const std::string& module, api_callback_fn callback) {
  callbacks_.module_callbacks[module].push_back(std::move(callback));
}

void api_dispatcher::register_category_callback(api_info::category category, api_callback_fn callback) {
  callbacks_.category_callbacks[category].push_back(std::move(callback));
}

void api_dispatcher::unregister_symbol_callback(const std::string& module, const std::string& symbol) {
  callbacks_.symbol_callbacks.erase(make_filter_key(module, symbol));
}

void api_dispatcher::unregister_module_callback(const std::string& module) { callbacks_.module_callbacks.erase(module); }

void api_dispatcher::unregister_category_callback(api_info::category category) {
  callbacks_.category_callbacks.erase(category);
}

void api_dispatcher::clear_all_callbacks() {
  callbacks_.symbol_callbacks.clear();
  callbacks_.module_callbacks.clear();
  callbacks_.category_callbacks.clear();
}

api_analyzer& api_dispatcher::get_analyzer() { return analyzer_; }

const api_knowledge_db& api_dispatcher::get_api_db() const { return analyzer_.get_api_db(); }

bool api_dispatcher::has_callbacks_for(
    const std::string& module, const std::string& symbol, api_info::category category
) const {
  auto key = make_filter_key(module, symbol);
  bool has_symbol = callbacks_.symbol_callbacks.count(key) > 0;
  bool has_module = callbacks_.module_callbacks.count(module) > 0;
  bool has_category = category != api_info::category::UNKNOWN && callbacks_.category_callbacks.count(category) > 0;
  return has_symbol || has_module || has_category;
}

void api_dispatcher::dispatch_event(const api_event& event) {
  auto key = make_filter_key(event.module_name, event.symbol_name);

  if (auto sym_it = callbacks_.symbol_callbacks.find(key); sym_it != callbacks_.symbol_callbacks.end()) {
    for (const auto& cb : sym_it->second) {
      cb(event);
    }
  }

  if (auto mod_it = callbacks_.module_callbacks.find(event.module_name); mod_it != callbacks_.module_callbacks.end()) {
    for (const auto& cb : mod_it->second) {
      cb(event);
    }
  }

  if (event.category != api_info::category::UNKNOWN) {
    if (auto cat_it = callbacks_.category_callbacks.find(event.category);
        cat_it != callbacks_.category_callbacks.end()) {
      for (const auto& cb : cat_it->second) {
        cb(event);
      }
    }
  }
}

std::string api_dispatcher::make_filter_key(const std::string& module, const std::string& symbol) const {
  return module + "|" + symbol;
}

api_call_tracker::tracked_call api_dispatcher::to_tracked_call(
    const api_context& ctx, const api_analysis_result& analysis
) const {
  api_call_tracker::tracked_call call;
  call.call_address = ctx.call_address;
  call.target_address = ctx.target_address;
  call.timestamp = ctx.timestamp;
  call.module_name = analysis.module_name.empty() ? ctx.module_name : analysis.module_name;
  call.symbol_name = analysis.symbol_name.empty() ? ctx.symbol_name : analysis.symbol_name;
  call.category = analysis.category;
  call.description = analysis.description;
  call.formatted_call = analysis.formatted_call;
  call.return_param = analysis.return_param;
  call.has_return_value = analysis.has_return_value;
  return call;
}

std::optional<api_event> api_dispatcher::analyze_call_internal(const api_context& ctx) {
  auto analysis = analyzer_.analyze_call(ctx);
  if (!analysis.analysis_complete) {
    return std::nullopt;
  }

  stats_.calls_analyzed++;

  if (analysis.has_return_value) {
    call_tracker_.record_call(to_tracked_call(ctx, analysis));
  }

  return api_event_builder::build_call_event(ctx, analysis);
}

std::optional<api_event> api_dispatcher::analyze_return_internal(
    const api_context& ctx, const api_call_tracker::tracked_call& call
) {
  api_context return_ctx = ctx;
  if (!call.module_name.empty()) {
    return_ctx.module_name = call.module_name;
  }
  if (!call.symbol_name.empty()) {
    return_ctx.symbol_name = call.symbol_name;
  }

  extracted_argument return_value = analyzer_.extract_return_value(return_ctx, call.return_param);

  api_analysis_result summary;
  summary.module_name = call.module_name;
  summary.symbol_name = call.symbol_name;
  summary.category = call.category;
  summary.description = call.description;
  summary.formatted_call = call.formatted_call;
  summary.analysis_complete = true;
  summary.has_return_value = call.has_return_value;

  stats_.returns_analyzed++;

  return api_event_builder::build_return_event(return_ctx, summary, return_value);
}

} // namespace w1::abi
