#include "api_analysis.hpp"
#include <redlog.hpp>

namespace w1::tracers::script::bindings {

namespace {

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

api_analysis_manager::api_analysis_manager() = default;

api_analysis_manager::~api_analysis_manager() { shutdown(); }

void api_analysis_manager::initialize(const util::module_range_index& index) {
  module_index_ = &index;
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

void api_analysis_manager::process_call(const abi::api_context& ctx) {
  if (listener_) {
    listener_->process_call(ctx);
  }
}

void api_analysis_manager::process_return(const abi::api_context& ctx) {
  if (listener_) {
    listener_->process_return(ctx);
  }
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

  // add API category enum to w1 module
  auto api_category = lua.new_enum<abi::api_info::category>(
      "ApiCategory", {{"UNKNOWN", abi::api_info::category::UNKNOWN},
                      {"FILE_IO", abi::api_info::category::FILE_IO},
                      {"FILE_MANAGEMENT", abi::api_info::category::FILE_MANAGEMENT},
                      {"STDIO", abi::api_info::category::STDIO},
                      {"DEVICE_IO", abi::api_info::category::DEVICE_IO},
                      {"PROCESS_CONTROL", abi::api_info::category::PROCESS_CONTROL},
                      {"THREAD_CONTROL", abi::api_info::category::THREAD_CONTROL},
                      {"THREADING", abi::api_info::category::THREADING},
                      {"MEMORY_MANAGEMENT", abi::api_info::category::MEMORY_MANAGEMENT},
                      {"HEAP_MANAGEMENT", abi::api_info::category::HEAP_MANAGEMENT},
                      {"SYNCHRONIZATION", abi::api_info::category::SYNCHRONIZATION},
                      {"MUTEX", abi::api_info::category::MUTEX},
                      {"EVENT", abi::api_info::category::EVENT},
                      {"SEMAPHORE", abi::api_info::category::SEMAPHORE},
                      {"NETWORK_SOCKET", abi::api_info::category::NETWORK_SOCKET},
                      {"NETWORK_DNS", abi::api_info::category::NETWORK_DNS},
                      {"NETWORK_HTTP", abi::api_info::category::NETWORK_HTTP},
                      {"REGISTRY", abi::api_info::category::REGISTRY},
                      {"SECURITY", abi::api_info::category::SECURITY},
                      {"CRYPTO", abi::api_info::category::CRYPTO},
                      {"SYSTEM_INFO", abi::api_info::category::SYSTEM_INFO},
                      {"TIME", abi::api_info::category::TIME},
                      {"ENVIRONMENT", abi::api_info::category::ENVIRONMENT},
                      {"STRING_MANIPULATION", abi::api_info::category::STRING_MANIPULATION},
                      {"LOCALE", abi::api_info::category::LOCALE},
                      {"LIBRARY_LOADING", abi::api_info::category::LIBRARY_LOADING},
                      {"MATH", abi::api_info::category::MATH},
                      {"SORTING", abi::api_info::category::SORTING},
                      {"IPC", abi::api_info::category::IPC},
                      {"PIPE", abi::api_info::category::PIPE},
                      {"SHARED_MEMORY", abi::api_info::category::SHARED_MEMORY},
                      {"UI", abi::api_info::category::UI},
                      {"WINDOW", abi::api_info::category::WINDOW},
                      {"SYSTEM_HOOK", abi::api_info::category::SYSTEM_HOOK},
                      {"MISC", abi::api_info::category::MISC}}
  );
  w1_module["ApiCategory"] = api_category;

  // also create a simple table for easier access
  sol::table api_category_table = lua.create_table();
  api_category_table["UNKNOWN"] = static_cast<int>(abi::api_info::category::UNKNOWN);
  api_category_table["FILE_IO"] = static_cast<int>(abi::api_info::category::FILE_IO);
  api_category_table["FILE_MANAGEMENT"] = static_cast<int>(abi::api_info::category::FILE_MANAGEMENT);
  api_category_table["STDIO"] = static_cast<int>(abi::api_info::category::STDIO);
  api_category_table["DEVICE_IO"] = static_cast<int>(abi::api_info::category::DEVICE_IO);
  api_category_table["PROCESS_CONTROL"] = static_cast<int>(abi::api_info::category::PROCESS_CONTROL);
  api_category_table["THREAD_CONTROL"] = static_cast<int>(abi::api_info::category::THREAD_CONTROL);
  api_category_table["THREADING"] = static_cast<int>(abi::api_info::category::THREADING);
  api_category_table["MEMORY_MANAGEMENT"] = static_cast<int>(abi::api_info::category::MEMORY_MANAGEMENT);
  api_category_table["HEAP_MANAGEMENT"] = static_cast<int>(abi::api_info::category::HEAP_MANAGEMENT);
  api_category_table["SYNCHRONIZATION"] = static_cast<int>(abi::api_info::category::SYNCHRONIZATION);
  api_category_table["MUTEX"] = static_cast<int>(abi::api_info::category::MUTEX);
  api_category_table["EVENT"] = static_cast<int>(abi::api_info::category::EVENT);
  api_category_table["SEMAPHORE"] = static_cast<int>(abi::api_info::category::SEMAPHORE);
  api_category_table["NETWORK_SOCKET"] = static_cast<int>(abi::api_info::category::NETWORK_SOCKET);
  api_category_table["NETWORK_DNS"] = static_cast<int>(abi::api_info::category::NETWORK_DNS);
  api_category_table["NETWORK_HTTP"] = static_cast<int>(abi::api_info::category::NETWORK_HTTP);
  api_category_table["REGISTRY"] = static_cast<int>(abi::api_info::category::REGISTRY);
  api_category_table["SECURITY"] = static_cast<int>(abi::api_info::category::SECURITY);
  api_category_table["CRYPTO"] = static_cast<int>(abi::api_info::category::CRYPTO);
  api_category_table["SYSTEM_INFO"] = static_cast<int>(abi::api_info::category::SYSTEM_INFO);
  api_category_table["TIME"] = static_cast<int>(abi::api_info::category::TIME);
  api_category_table["ENVIRONMENT"] = static_cast<int>(abi::api_info::category::ENVIRONMENT);
  api_category_table["STRING_MANIPULATION"] = static_cast<int>(abi::api_info::category::STRING_MANIPULATION);
  api_category_table["LOCALE"] = static_cast<int>(abi::api_info::category::LOCALE);
  api_category_table["LIBRARY_LOADING"] = static_cast<int>(abi::api_info::category::LIBRARY_LOADING);
  api_category_table["MATH"] = static_cast<int>(abi::api_info::category::MATH);
  api_category_table["SORTING"] = static_cast<int>(abi::api_info::category::SORTING);
  api_category_table["IPC"] = static_cast<int>(abi::api_info::category::IPC);
  api_category_table["PIPE"] = static_cast<int>(abi::api_info::category::PIPE);
  api_category_table["SHARED_MEMORY"] = static_cast<int>(abi::api_info::category::SHARED_MEMORY);
  api_category_table["UI"] = static_cast<int>(abi::api_info::category::UI);
  api_category_table["WINDOW"] = static_cast<int>(abi::api_info::category::WINDOW);
  api_category_table["SYSTEM_HOOK"] = static_cast<int>(abi::api_info::category::SYSTEM_HOOK);
  api_category_table["MISC"] = static_cast<int>(abi::api_info::category::MISC);
  w1_module["API_CATEGORY"] = api_category_table;

  // add utility function to get category name strings
  w1_module["api_category_name"] = [](abi::api_info::category category) -> std::string {
    switch (category) {
    case abi::api_info::category::UNKNOWN:
      return "unknown";
    case abi::api_info::category::FILE_IO:
      return "file_io";
    case abi::api_info::category::FILE_MANAGEMENT:
      return "file_mgmt";
    case abi::api_info::category::STDIO:
      return "stdio";
    case abi::api_info::category::DEVICE_IO:
      return "device_io";
    case abi::api_info::category::PROCESS_CONTROL:
      return "process";
    case abi::api_info::category::THREAD_CONTROL:
      return "thread";
    case abi::api_info::category::THREADING:
      return "threading";
    case abi::api_info::category::MEMORY_MANAGEMENT:
      return "memory";
    case abi::api_info::category::HEAP_MANAGEMENT:
      return "heap";
    case abi::api_info::category::SYNCHRONIZATION:
      return "sync";
    case abi::api_info::category::MUTEX:
      return "mutex";
    case abi::api_info::category::EVENT:
      return "event";
    case abi::api_info::category::SEMAPHORE:
      return "semaphore";
    case abi::api_info::category::NETWORK_SOCKET:
      return "network";
    case abi::api_info::category::NETWORK_DNS:
      return "dns";
    case abi::api_info::category::NETWORK_HTTP:
      return "http";
    case abi::api_info::category::REGISTRY:
      return "registry";
    case abi::api_info::category::SECURITY:
      return "security";
    case abi::api_info::category::CRYPTO:
      return "crypto";
    case abi::api_info::category::SYSTEM_INFO:
      return "system";
    case abi::api_info::category::TIME:
      return "time";
    case abi::api_info::category::ENVIRONMENT:
      return "environment";
    case abi::api_info::category::STRING_MANIPULATION:
      return "string";
    case abi::api_info::category::LOCALE:
      return "locale";
    case abi::api_info::category::LIBRARY_LOADING:
      return "library";
    case abi::api_info::category::MATH:
      return "math";
    case abi::api_info::category::SORTING:
      return "sorting";
    case abi::api_info::category::IPC:
      return "ipc";
    case abi::api_info::category::PIPE:
      return "pipe";
    case abi::api_info::category::SHARED_MEMORY:
      return "shared_memory";
    case abi::api_info::category::UI:
      return "ui";
    case abi::api_info::category::WINDOW:
      return "window";
    case abi::api_info::category::SYSTEM_HOOK:
      return "system_hook";
    case abi::api_info::category::MISC:
      return "misc";
    default:
      return "category_" + std::to_string(static_cast<int>(category));
    }
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