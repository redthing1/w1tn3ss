#include "api_analysis.hpp"
#include <w1tn3ss/util/register_access.hpp>
#include <redlog.hpp>
#include <chrono>

namespace w1::tracers::script::bindings {

namespace {

// single source of truth for api categories
struct api_category_info {
  abi::api_info::category value;
  const char* enum_name;
  const char* short_name;
};

static constexpr api_category_info API_CATEGORIES[] = {
    {abi::api_info::category::UNKNOWN, "UNKNOWN", "unknown"},
    {abi::api_info::category::FILE_IO, "FILE_IO", "file_io"},
    {abi::api_info::category::FILE_MANAGEMENT, "FILE_MANAGEMENT", "file_mgmt"},
    {abi::api_info::category::STDIO, "STDIO", "stdio"},
    {abi::api_info::category::DEVICE_IO, "DEVICE_IO", "device_io"},
    {abi::api_info::category::PROCESS_CONTROL, "PROCESS_CONTROL", "process"},
    {abi::api_info::category::THREAD_CONTROL, "THREAD_CONTROL", "thread"},
    {abi::api_info::category::THREADING, "THREADING", "threading"},
    {abi::api_info::category::MEMORY_MANAGEMENT, "MEMORY_MANAGEMENT", "memory"},
    {abi::api_info::category::HEAP_MANAGEMENT, "HEAP_MANAGEMENT", "heap"},
    {abi::api_info::category::SYNCHRONIZATION, "SYNCHRONIZATION", "sync"},
    {abi::api_info::category::MUTEX, "MUTEX", "mutex"},
    {abi::api_info::category::EVENT, "EVENT", "event"},
    {abi::api_info::category::SEMAPHORE, "SEMAPHORE", "semaphore"},
    {abi::api_info::category::NETWORK_SOCKET, "NETWORK_SOCKET", "network"},
    {abi::api_info::category::NETWORK_DNS, "NETWORK_DNS", "dns"},
    {abi::api_info::category::NETWORK_HTTP, "NETWORK_HTTP", "http"},
    {abi::api_info::category::REGISTRY, "REGISTRY", "registry"},
    {abi::api_info::category::SECURITY, "SECURITY", "security"},
    {abi::api_info::category::CRYPTO, "CRYPTO", "crypto"},
    {abi::api_info::category::SYSTEM_INFO, "SYSTEM_INFO", "system"},
    {abi::api_info::category::TIME, "TIME", "time"},
    {abi::api_info::category::ENVIRONMENT, "ENVIRONMENT", "environment"},
    {abi::api_info::category::STRING_MANIPULATION, "STRING_MANIPULATION", "string"},
    {abi::api_info::category::LOCALE, "LOCALE", "locale"},
    {abi::api_info::category::LIBRARY_LOADING, "LIBRARY_LOADING", "library"},
    {abi::api_info::category::MATH, "MATH", "math"},
    {abi::api_info::category::SORTING, "SORTING", "sorting"},
    {abi::api_info::category::IPC, "IPC", "ipc"},
    {abi::api_info::category::PIPE, "PIPE", "pipe"},
    {abi::api_info::category::SHARED_MEMORY, "SHARED_MEMORY", "shared_memory"},
    {abi::api_info::category::UI, "UI", "ui"},
    {abi::api_info::category::WINDOW, "WINDOW", "window"},
    {abi::api_info::category::SYSTEM_HOOK, "SYSTEM_HOOK", "system_hook"},
    {abi::api_info::category::MISC, "MISC", "misc"}
};

// convert C++ api_event to Lua table
sol::table convert_api_event_to_lua(sol::state_view lua, const abi::api_event& event) {
  auto result = lua.create_table();

  // basic event info
  result["type"] = (event.type == abi::api_event::event_type::CALL) ? "call" : "return";
  result["timestamp"] = event.timestamp;
  result["source_address"] = event.source_address;
  result["target_address"] = event.target_address;

  // api identification
  result["module_name"] = event.module_name;
  result["symbol_name"] = event.symbol_name;
  result["category"] = static_cast<int>(event.category);
  result["description"] = event.description;
  result["formatted_call"] = event.formatted_call;
  result["analysis_complete"] = event.analysis_complete;

  // convert arguments
  auto args_table = lua.create_table();
  for (size_t i = 0; i < event.arguments.size(); ++i) {
    const auto& arg = event.arguments[i];
    auto arg_table = lua.create_table();
    arg_table["raw_value"] = arg.raw_value;
    arg_table["param_name"] = arg.param_name;
    arg_table["param_type"] = static_cast<int>(arg.param_type);
    arg_table["interpreted_value"] = arg.interpreted_value;
    arg_table["is_pointer"] = arg.is_pointer;
    args_table[i + 1] = arg_table; // Lua arrays are 1-indexed
  }
  result["arguments"] = args_table;

  // convert return value if present
  if (event.return_value.has_value()) {
    const auto& ret = event.return_value.value();
    auto ret_table = lua.create_table();
    ret_table["raw_value"] = ret.raw_value;
    ret_table["param_type"] = static_cast<int>(ret.param_type);
    ret_table["interpreted_value"] = ret.interpreted_value;
    ret_table["is_pointer"] = ret.is_pointer;
    result["return_value"] = ret_table;
  }

  return result;
}

} // anonymous namespace

// api_analysis_manager implementation

api_analysis_manager::api_analysis_manager() : logger_(redlog::get_logger("w1.api_analysis_manager")) {}

api_analysis_manager::~api_analysis_manager() { shutdown(); }

void api_analysis_manager::initialize(const util::module_range_index& index, symbols::symbol_resolver* resolver) {
  module_index_ = &index;
  symbol_resolver_ = resolver;
  initialized_ = true;

  // initialize listener if it was already created
  if (listener_) {
    listener_->initialize(index);
  }
}

void api_analysis_manager::ensure_listener() {
  if (!listener_) {
    auto logger = redlog::get_logger("w1.script_api_analysis");
    logger.inf("creating api_listener on first use");

    // create with default config
    abi::analyzer_config cfg;
    cfg.extract_arguments = true;
    cfg.format_calls = true;
    cfg.max_string_length = 256;

    listener_ = std::make_unique<abi::api_listener>(cfg);

    // initialize if we already have module index
    if (initialized_ && module_index_) {
      logger.inf("initializing api_listener with module index");
      listener_->initialize(*module_index_);
    }
  }
}

void api_analysis_manager::process_call(
    QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!module_index_ || !listener_) {
    return;
  }

  // build api context (absorbed from api_processor)
  w1::abi::api_context ctx;
  ctx.vm = vm;
  ctx.vm_state = state;
  ctx.gpr_state = gpr;
  ctx.fpr_state = fpr;
  ctx.module_index = module_index_;
  ctx.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();

  // for calls: source is where we're calling from, target is what we're calling
  ctx.call_address = state->sequenceStart;
  ctx.target_address = w1::registers::get_pc(gpr);

  // get module and symbol names
  if (auto module_info = module_index_->find_containing(ctx.target_address)) {
    ctx.module_name = module_info->name;

    // resolve symbol if we have a resolver
    if (symbol_resolver_) {
      if (auto sym_info = symbol_resolver_->resolve_address(ctx.target_address, *module_index_)) {
        ctx.symbol_name = sym_info->name;
      }
    }
  }

  logger_.dbg(
      "processing api call", redlog::field("target", ctx.target_address), redlog::field("module", ctx.module_name),
      redlog::field("symbol", ctx.symbol_name)
  );

  listener_->process_call(ctx);
}

void api_analysis_manager::process_return(
    QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!module_index_ || !listener_) {
    return;
  }

  // build api context (absorbed from api_processor)
  w1::abi::api_context ctx;
  ctx.vm = vm;
  ctx.vm_state = state;
  ctx.gpr_state = gpr;
  ctx.fpr_state = fpr;
  ctx.module_index = module_index_;
  ctx.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();

  // for returns: source is what we're returning from, target is where we're returning to
  ctx.target_address = state->sequenceStart;
  ctx.call_address = w1::registers::get_pc(gpr);

  // get module and symbol names
  if (auto module_info = module_index_->find_containing(ctx.target_address)) {
    ctx.module_name = module_info->name;

    // resolve symbol if we have a resolver
    if (symbol_resolver_) {
      if (auto sym_info = symbol_resolver_->resolve_address(ctx.target_address, *module_index_)) {
        ctx.symbol_name = sym_info->name;
      }
    }
  }

  listener_->process_return(ctx);
}

void api_analysis_manager::shutdown() {
  if (listener_) {
    auto logger = redlog::get_logger("w1.script_api_analysis");
    logger.dbg("shutting down api_listener");
    listener_->clear_all_callbacks();
    listener_.reset();
  }
}

// setup function

void setup_api_analysis(
    sol::state& lua, sol::table& w1_module, sol::table& tracer_table, std::shared_ptr<api_analysis_manager>& manager
) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up api analysis bindings");

  // ensure manager exists
  if (!manager) {
    manager = std::make_shared<api_analysis_manager>();
  }

  // create api category table from centralized data
  sol::table api_category = lua.create_table();
  for (const auto& cat_info : API_CATEGORIES) {
    api_category[cat_info.enum_name] = cat_info.value;
  }
  w1_module["ApiCategory"] = api_category;

  // also create a simple table for easier access - built from centralized data
  sol::table api_category_table = lua.create_table();
  for (const auto& cat_info : API_CATEGORIES) {
    api_category_table[cat_info.enum_name] = static_cast<int>(cat_info.value);
  }
  w1_module["API_CATEGORY"] = api_category_table;

  // add utility function to get category name strings - built from centralized data
  w1_module["api_category_name"] = [](abi::api_info::category category) -> std::string {
    for (const auto& cat_info : API_CATEGORIES) {
      if (cat_info.value == category) {
        return cat_info.short_name;
      }
    }
    return "category_" + std::to_string(static_cast<int>(category));
  };

  // capture manager by value (shared_ptr) to ensure it outlives callbacks
  // note: we rely on the script_tracer to keep the lua state alive

  // add registration functions to the tracer table
  tracer_table["register_api_symbol_callback"] = [manager](
                                                     sol::this_state ts, const std::string& module,
                                                     const std::string& symbol, sol::protected_function callback
                                                 ) {
    lua_State* L = ts;
    manager->ensure_listener();
    manager->get_listener()->register_symbol_callback(module, symbol, [L, callback](const abi::api_event& event) {
      sol::state_view lua(L);
      auto lua_event = convert_api_event_to_lua(lua, event);
      auto result = callback(lua_event);
      if (!result.valid()) {
        sol::error err = result;
        auto log = redlog::get_logger("w1.script_api_analysis");
        log.err("error in api symbol callback", redlog::field("error", err.what()));
      }
    });
  };

  tracer_table["register_api_module_callback"] =
      [manager](sol::this_state ts, const std::string& module, sol::protected_function callback) {
        lua_State* L = ts;
        manager->ensure_listener();
        manager->get_listener()->register_module_callback(module, [L, callback](const abi::api_event& event) {
          sol::state_view lua(L);
          auto lua_event = convert_api_event_to_lua(lua, event);
          auto result = callback(lua_event);
          if (!result.valid()) {
            sol::error err = result;
            auto log = redlog::get_logger("w1.script_api_analysis");
            log.err("error in api module callback", redlog::field("error", err.what()));
          }
        });
      };

  tracer_table["register_api_category_callback"] =
      [manager](sol::this_state ts, abi::api_info::category category, sol::protected_function callback) {
        lua_State* L = ts;
        manager->ensure_listener();
        manager->get_listener()->register_category_callback(category, [L, callback](const abi::api_event& event) {
          sol::state_view lua(L);
          auto lua_event = convert_api_event_to_lua(lua, event);
          auto result = callback(lua_event);
          if (!result.valid()) {
            sol::error err = result;
            auto log = redlog::get_logger("w1.script_api_analysis");
            log.err("error in api category callback", redlog::field("error", err.what()));
          }
        });
      };

  logger.dbg("api analysis bindings registered successfully");
}

} // namespace w1::tracers::script::bindings