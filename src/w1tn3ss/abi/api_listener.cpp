#include "api_listener.hpp"
#include "api_analyzer.hpp"
#include "../util/module_range_index.hpp"
#include "../util/value_formatter.hpp"
#include <redlog.hpp>
#include <algorithm>
#include <chrono>

namespace w1::abi {

// pending call info for return matching
struct pending_call {
  uint64_t call_target_address;
  std::string target_symbol_name;
  std::string target_module;
  api_info api_info;
  uint64_t timestamp;
};

class api_listener::impl {
public:
  explicit impl(const analyzer_config& config);
  
  // constants
  static constexpr size_t MAX_PENDING_CALLS = 10000;
  
  // callbacks
  std::unordered_map<std::string, std::vector<api_callback_fn>> symbol_callbacks_;  // "module|symbol" -> callbacks
  std::unordered_map<std::string, std::vector<api_callback_fn>> module_callbacks_;
  std::unordered_map<api_info::category, std::vector<api_callback_fn>> category_callbacks_;
  
  // api analyzer
  std::unique_ptr<api_analyzer> analyzer_;
  
  // pending calls for return matching
  std::vector<pending_call> call_stack_;
  
  // statistics
  stats stats_;
  
  // logger
  redlog::logger log_;
  
  // helper methods
  bool has_callbacks_for(const std::string& module, const std::string& symbol, api_info::category category) const;
  api_event create_event_from_analysis(const api_analysis_result& analysis, const api_context& ctx, 
                                       api_event::event_type type);
  void dispatch_event(const api_event& event);
  std::string make_filter_key(const std::string& module, const std::string& symbol) const;
  std::optional<pending_call> find_and_remove_matching_call(uint64_t return_from_address);
};

api_listener::impl::impl(const analyzer_config& config)
    : analyzer_(std::make_unique<api_analyzer>(config)),
      stats_{},
      log_("w1.api_listener") {
}

bool api_listener::impl::has_callbacks_for(const std::string& module, const std::string& symbol, 
                                            api_info::category category) const {
  // check if any callbacks are registered for this API
  auto key = make_filter_key(module, symbol);
  bool has_symbol_cb = symbol_callbacks_.count(key) > 0;
  bool has_module_cb = module_callbacks_.count(module) > 0;
  bool has_category_cb = category != api_info::category::UNKNOWN && category_callbacks_.count(category) > 0;
  
  log_.dbg("checking callbacks", redlog::field("module", module), redlog::field("symbol", symbol),
          redlog::field("key", key), redlog::field("category", static_cast<int>(category)),
          redlog::field("has_symbol_cb", has_symbol_cb), 
          redlog::field("has_module_cb", has_module_cb),
          redlog::field("has_category_cb", has_category_cb));
  
  return has_symbol_cb || has_module_cb || has_category_cb;
}

api_event api_listener::impl::create_event_from_analysis(const api_analysis_result& analysis, 
                                                          const api_context& ctx,
                                                          api_event::event_type type) {
  api_event event;
  event.type = type;
  event.timestamp = ctx.timestamp;
  event.source_address = ctx.call_address;
  event.target_address = ctx.target_address;
  event.module_name = ctx.module_name;
  event.symbol_name = ctx.symbol_name;
  event.category = analysis.category;
  event.description = analysis.description;
  event.formatted_call = analysis.formatted_call;
  event.analysis_complete = analysis.analysis_complete;
  
  // convert arguments
  w1::util::value_formatter::format_options fmt_opts;
  fmt_opts.max_string_length = 256;
  
  for (const auto& arg : analysis.arguments) {
    api_event::argument evt_arg;
    evt_arg.raw_value = arg.raw_value;
    evt_arg.param_name = arg.param_name;
    evt_arg.param_type = arg.param_type;
    evt_arg.is_pointer = arg.is_valid_pointer;
    
    // format interpreted value
    if (!arg.string_preview.empty()) {
      evt_arg.interpreted_value = w1::util::value_formatter::format_string(arg.string_preview, fmt_opts);
    } else if (arg.is_null_pointer) {
      evt_arg.interpreted_value = "NULL";
    } else if (std::holds_alternative<std::string>(arg.interpreted_value)) {
      evt_arg.interpreted_value = 
          w1::util::value_formatter::format_string(std::get<std::string>(arg.interpreted_value), fmt_opts);
    } else if (std::holds_alternative<bool>(arg.interpreted_value)) {
      evt_arg.interpreted_value = w1::util::value_formatter::format_bool(std::get<bool>(arg.interpreted_value));
    } else if (std::holds_alternative<std::vector<uint8_t>>(arg.interpreted_value)) {
      evt_arg.interpreted_value = 
          w1::util::value_formatter::format_buffer(std::get<std::vector<uint8_t>>(arg.interpreted_value), fmt_opts);
    } else {
      // fallback to type-based formatting
      auto value_type = w1::util::value_formatter::value_type::UNKNOWN;
      if (arg.param_type == param_info::type::BOOLEAN) {
        value_type = w1::util::value_formatter::value_type::BOOLEAN;
      } else if (arg.param_type == param_info::type::ERROR_CODE) {
        value_type = w1::util::value_formatter::value_type::ERROR_CODE;
      } else if (arg.is_valid_pointer) {
        value_type = w1::util::value_formatter::value_type::POINTER;
      }
      evt_arg.interpreted_value = w1::util::value_formatter::format_typed_value(arg.raw_value, value_type, fmt_opts);
    }
    
    event.arguments.push_back(evt_arg);
  }
  
  // handle return value if present
  if (type == api_event::event_type::RETURN && analysis.return_value.param_type != param_info::type::VOID) {
    const auto& ret_val = analysis.return_value;
    api_event::argument evt_ret;
    evt_ret.raw_value = ret_val.raw_value;
    evt_ret.param_type = ret_val.param_type;
    evt_ret.is_pointer = ret_val.is_valid_pointer;
    
    // format return value
    if (!ret_val.string_preview.empty()) {
      evt_ret.interpreted_value = w1::util::value_formatter::format_string(ret_val.string_preview, fmt_opts);
    } else if (ret_val.is_null_pointer) {
      evt_ret.interpreted_value = "NULL";
    } else if (std::holds_alternative<std::string>(ret_val.interpreted_value)) {
      evt_ret.interpreted_value = 
          w1::util::value_formatter::format_string(std::get<std::string>(ret_val.interpreted_value), fmt_opts);
    } else if (std::holds_alternative<bool>(ret_val.interpreted_value)) {
      evt_ret.interpreted_value = w1::util::value_formatter::format_bool(std::get<bool>(ret_val.interpreted_value));
    } else {
      // fallback to type-based formatting
      auto value_type = w1::util::value_formatter::value_type::UNKNOWN;
      if (ret_val.param_type == param_info::type::BOOLEAN) {
        value_type = w1::util::value_formatter::value_type::BOOLEAN;
      } else if (ret_val.param_type == param_info::type::ERROR_CODE) {
        value_type = w1::util::value_formatter::value_type::ERROR_CODE;
      } else if (ret_val.is_valid_pointer) {
        value_type = w1::util::value_formatter::value_type::POINTER;
      }
      evt_ret.interpreted_value = w1::util::value_formatter::format_typed_value(ret_val.raw_value, value_type, fmt_opts);
    }
    
    event.return_value = evt_ret;
  }
  
  return event;
}

void api_listener::impl::dispatch_event(const api_event& event) {
  // dispatch to specific callbacks
  auto key = make_filter_key(event.module_name, event.symbol_name);
  
  // symbol callbacks
  auto sym_it = symbol_callbacks_.find(key);
  if (sym_it != symbol_callbacks_.end()) {
    for (const auto& cb : sym_it->second) {
      cb(event);
    }
  }
  
  // module callbacks
  auto mod_it = module_callbacks_.find(event.module_name);
  if (mod_it != module_callbacks_.end()) {
    for (const auto& cb : mod_it->second) {
      cb(event);
    }
  }
  
  // category callbacks
  if (event.category != api_info::category::UNKNOWN) {
    auto cat_it = category_callbacks_.find(event.category);
    if (cat_it != category_callbacks_.end()) {
      for (const auto& cb : cat_it->second) {
        cb(event);
      }
    }
  }
}

std::optional<pending_call> api_listener::impl::find_and_remove_matching_call(uint64_t return_from_address) {
  // search in reverse order for most recent call
  auto call_it = std::find_if(call_stack_.rbegin(), call_stack_.rend(),
                              [return_from_address](const pending_call& call) {
                                return call.call_target_address == return_from_address;
                              });
  
  if (call_it != call_stack_.rend()) {
    pending_call result = *call_it;
    // remove from stack (convert reverse iterator to forward iterator for erase)
    call_stack_.erase(std::next(call_it).base());
    return result;
  }
  return std::nullopt;
}

std::string api_listener::impl::make_filter_key(const std::string& module, const std::string& symbol) const {
  return module + "|" + symbol;
}

// api_listener public interface implementation

api_listener::api_listener(const analyzer_config& config) : pimpl_(std::make_unique<impl>(config)) {}

api_listener::~api_listener() = default;

void api_listener::initialize(const util::module_range_index& index) {
  pimpl_->analyzer_->initialize(index);
}

// direct analysis methods for w1xfer
std::optional<api_event> api_listener::analyze_call(const api_context& ctx) {
  pimpl_->stats_.total_calls_processed++;
  
  // perform analysis
  auto analysis = pimpl_->analyzer_->analyze_call(ctx);
  
  // if not an API, return empty
  if (!analysis.analysis_complete || analysis.category == api_info::category::UNKNOWN) {
    return std::nullopt;
  }
  
  pimpl_->stats_.calls_analyzed++;
  
  // track for return matching if has return value
  if (auto api_info = pimpl_->analyzer_->get_api_db().lookup(analysis.symbol_name)) {
    if (api_info->return_value.param_type != param_info::type::VOID) {
      pending_call pending;
      pending.call_target_address = ctx.target_address;
      pending.target_symbol_name = ctx.symbol_name;
      pending.target_module = ctx.module_name;
      pending.api_info = *api_info;
      pending.timestamp = ctx.timestamp;
      
      // limit call stack size to prevent unbounded growth
      if (pimpl_->call_stack_.size() >= impl::MAX_PENDING_CALLS) {
        pimpl_->log_.wrn("pending call stack limit reached, removing oldest entry");
        pimpl_->call_stack_.erase(pimpl_->call_stack_.begin());
      }
      
      pimpl_->call_stack_.push_back(pending);
    }
  }
  
  // create and return event
  return pimpl_->create_event_from_analysis(analysis, ctx, api_event::event_type::CALL);
}

std::optional<api_event> api_listener::analyze_return(const api_context& ctx) {
  pimpl_->stats_.total_returns_processed++;
  
  // find and remove matching call
  auto source_addr = ctx.target_address; // function we're returning from
  auto matching_call = pimpl_->find_and_remove_matching_call(source_addr);
  
  if (!matching_call) {
    return std::nullopt;
  }
  
  // create analysis result from matching call
  api_analysis_result return_analysis;
  return_analysis.symbol_name = matching_call->target_symbol_name;
  return_analysis.module_name = matching_call->target_module;
  return_analysis.category = matching_call->api_info.api_category;
  return_analysis.description = matching_call->api_info.description;
  return_analysis.analysis_complete = true;
  
  // analyze return value
  pimpl_->analyzer_->analyze_return(return_analysis, ctx);
  pimpl_->stats_.returns_analyzed++;
  
  // create and return event
  return pimpl_->create_event_from_analysis(return_analysis, ctx, api_event::event_type::RETURN);
}

void api_listener::register_symbol_callback(const std::string& module, const std::string& symbol,
                                            api_callback_fn callback) {
  auto key = pimpl_->make_filter_key(module, symbol);
  pimpl_->symbol_callbacks_[key].push_back(callback);
  
  pimpl_->log_.inf("registered symbol callback", redlog::field("module", module), 
          redlog::field("symbol", symbol), redlog::field("key", key),
          redlog::field("total_callbacks", pimpl_->symbol_callbacks_[key].size()));
}

void api_listener::register_module_callback(const std::string& module, api_callback_fn callback) {
  pimpl_->module_callbacks_[module].push_back(callback);
}

void api_listener::register_category_callback(api_info::category category, api_callback_fn callback) {
  pimpl_->category_callbacks_[category].push_back(callback);
}

void api_listener::unregister_symbol_callback(const std::string& module, const std::string& symbol) {
  auto key = pimpl_->make_filter_key(module, symbol);
  pimpl_->symbol_callbacks_.erase(key);
}

void api_listener::unregister_module_callback(const std::string& module) {
  pimpl_->module_callbacks_.erase(module);
}

void api_listener::unregister_category_callback(api_info::category category) {
  pimpl_->category_callbacks_.erase(category);
}

void api_listener::clear_all_callbacks() {
  pimpl_->symbol_callbacks_.clear();
  pimpl_->module_callbacks_.clear();
  pimpl_->category_callbacks_.clear();
}

// callback-based processing for scripts
void api_listener::process_call(const api_context& ctx) {
  pimpl_->stats_.total_calls_processed++;
  
  // check if we have any callbacks for this API
  auto initial_category = api_info::category::UNKNOWN;
  if (auto api_info = pimpl_->analyzer_->get_api_db().lookup(ctx.symbol_name)) {
    initial_category = api_info->api_category;
  }
  
  if (!pimpl_->has_callbacks_for(ctx.module_name, ctx.symbol_name, initial_category)) {
    pimpl_->stats_.calls_filtered_out++;
    return;
  }
  
  // analyze if we have callbacks
  if (auto event = analyze_call(ctx)) {
    pimpl_->dispatch_event(*event);
  }
}

void api_listener::process_return(const api_context& ctx) {
  pimpl_->stats_.total_returns_processed++;
  
  // peek at the matching call to check if we have callbacks
  auto source_addr = ctx.target_address; // function we're returning from
  auto call_it = std::find_if(pimpl_->call_stack_.rbegin(), pimpl_->call_stack_.rend(),
                              [source_addr](const pending_call& call) {
                                return call.call_target_address == source_addr;
                              });
  
  if (call_it == pimpl_->call_stack_.rend()) {
    return; // no matching call
  }
  
  // check if we have callbacks for this return
  if (!pimpl_->has_callbacks_for(call_it->target_module, call_it->target_symbol_name, 
                                  call_it->api_info.api_category)) {
    pimpl_->stats_.calls_filtered_out++;
    return;
  }
  
  // analyze if we have callbacks
  if (auto event = analyze_return(ctx)) {
    pimpl_->dispatch_event(*event);
  }
}

api_analyzer& api_listener::get_analyzer() {
  return *pimpl_->analyzer_;
}

const api_knowledge_db& api_listener::get_api_db() const {
  return pimpl_->analyzer_->get_api_db();
}

api_listener::stats api_listener::get_stats() const {
  return pimpl_->stats_;
}

} // namespace w1::abi