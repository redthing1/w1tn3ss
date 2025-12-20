#include "api_manager.hpp"

#include <w1tn3ss/util/register_access.hpp>

#include <chrono>

namespace w1::tracers::script::runtime {

api_manager::api_manager() : logger_(redlog::get_logger("w1.script_api")) {}

void api_manager::initialize(const w1::util::module_range_index& index, w1::symbols::symbol_resolver* resolver) {
  module_index_ = &index;
  symbol_resolver_ = resolver;
  initialized_ = true;

  if (listener_) {
    listener_->initialize(index);
  }
}

void api_manager::refresh_modules(const w1::util::module_range_index& index) {
  module_index_ = &index;
  if (listener_) {
    listener_->initialize(index);
  }
}

void api_manager::ensure_listener() {
  if (listener_) {
    return;
  }

  w1::abi::analyzer_config cfg;
  cfg.extract_arguments = true;
  cfg.format_calls = true;
  cfg.max_string_length = 256;

  listener_ = std::make_unique<w1::abi::api_listener>(cfg);
  if (initialized_ && module_index_) {
    listener_->initialize(*module_index_);
  }

  logger_.inf("created api listener");
}

sol::table api_manager::to_lua_event(const w1::abi::api_event& event) const {
  sol::state_view lua(lua_state_);
  sol::table result = lua.create_table();

  result["type"] = (event.type == w1::abi::api_event::event_type::CALL) ? "call" : "return";
  result["timestamp"] = event.timestamp;
  result["source_address"] = event.source_address;
  result["target_address"] = event.target_address;
  result["module_name"] = event.module_name;
  result["symbol_name"] = event.symbol_name;
  result["category"] = static_cast<int>(event.category);
  result["description"] = event.description;
  result["formatted_call"] = event.formatted_call;
  result["analysis_complete"] = event.analysis_complete;

  sol::table args_table = lua.create_table();
  for (size_t i = 0; i < event.arguments.size(); ++i) {
    const auto& arg = event.arguments[i];
    sol::table arg_table = lua.create_table();
    arg_table["raw_value"] = arg.raw_value;
    arg_table["param_name"] = arg.param_name;
    arg_table["param_type"] = static_cast<int>(arg.param_type);
    arg_table["interpreted_value"] = arg.interpreted_value;
    arg_table["is_pointer"] = arg.is_pointer;
    args_table[i + 1] = arg_table;
  }
  result["arguments"] = args_table;

  if (event.return_value.has_value()) {
    const auto& ret = event.return_value.value();
    sol::table ret_table = lua.create_table();
    ret_table["raw_value"] = ret.raw_value;
    ret_table["param_type"] = static_cast<int>(ret.param_type);
    ret_table["interpreted_value"] = ret.interpreted_value;
    ret_table["is_pointer"] = ret.is_pointer;
    result["return_value"] = ret_table;
  }

  return result;
}

void api_manager::register_symbol_callback(
    const std::string& module, const std::string& symbol, sol::protected_function callback
) {
  ensure_listener();
  callback_count_++;

  listener_->register_symbol_callback(
      module, symbol,
      [this, callback](const w1::abi::api_event& event) {
        if (!lua_state_) {
          return;
        }
        auto lua_event = to_lua_event(event);
        auto result = callback(lua_event);
        if (!result.valid()) {
          sol::error err = result;
          logger_.err("error in api symbol callback", redlog::field("error", err.what()));
        }
      }
  );
}

void api_manager::register_module_callback(const std::string& module, sol::protected_function callback) {
  ensure_listener();
  callback_count_++;

  listener_->register_module_callback(
      module,
      [this, callback](const w1::abi::api_event& event) {
        if (!lua_state_) {
          return;
        }
        auto lua_event = to_lua_event(event);
        auto result = callback(lua_event);
        if (!result.valid()) {
          sol::error err = result;
          logger_.err("error in api module callback", redlog::field("error", err.what()));
        }
      }
  );
}

void api_manager::register_category_callback(w1::abi::api_info::category category, sol::protected_function callback) {
  ensure_listener();
  callback_count_++;

  listener_->register_category_callback(
      category,
      [this, callback](const w1::abi::api_event& event) {
        if (!lua_state_) {
          return;
        }
        auto lua_event = to_lua_event(event);
        auto result = callback(lua_event);
        if (!result.valid()) {
          sol::error err = result;
          logger_.err("error in api category callback", redlog::field("error", err.what()));
        }
      }
  );
}

void api_manager::process_call(QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
  if (!listener_ || !module_index_) {
    return;
  }

  w1::abi::api_context ctx;
  ctx.vm = vm;
  ctx.vm_state = state;
  ctx.gpr_state = gpr;
  ctx.fpr_state = fpr;
  ctx.module_index = module_index_;
  ctx.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();

  ctx.call_address = state->sequenceStart;
  ctx.target_address = w1::registers::get_pc(gpr);

  if (auto module_info = module_index_->find_containing(ctx.target_address)) {
    ctx.module_name = module_info->name;
    if (symbol_resolver_) {
      if (auto sym_info = symbol_resolver_->resolve_address(ctx.target_address, *module_index_)) {
        ctx.symbol_name = sym_info->name;
      }
    }
  }

  listener_->process_call(ctx);
}

void api_manager::process_return(
    QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!listener_ || !module_index_) {
    return;
  }

  w1::abi::api_context ctx;
  ctx.vm = vm;
  ctx.vm_state = state;
  ctx.gpr_state = gpr;
  ctx.fpr_state = fpr;
  ctx.module_index = module_index_;
  ctx.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();

  ctx.target_address = state->sequenceStart;
  ctx.call_address = w1::registers::get_pc(gpr);

  if (auto module_info = module_index_->find_containing(ctx.target_address)) {
    ctx.module_name = module_info->name;
    if (symbol_resolver_) {
      if (auto sym_info = symbol_resolver_->resolve_address(ctx.target_address, *module_index_)) {
        ctx.symbol_name = sym_info->name;
      }
    }
  }

  listener_->process_return(ctx);
}

void api_manager::shutdown() {
  if (listener_) {
    listener_->clear_all_callbacks();
    listener_.reset();
  }
  callback_count_ = 0;
}

} // namespace w1::tracers::script::runtime
