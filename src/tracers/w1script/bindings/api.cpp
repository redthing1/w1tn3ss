#include "api.hpp"

#include <redlog.hpp>

namespace w1::tracers::script::bindings {

namespace {

struct api_category_info {
  w1::abi::api_info::category value;
  const char* enum_name;
  const char* short_name;
};

static constexpr api_category_info API_CATEGORIES[] = {
    {w1::abi::api_info::category::UNKNOWN, "UNKNOWN", "unknown"},
    {w1::abi::api_info::category::FILE_IO, "FILE_IO", "file_io"},
    {w1::abi::api_info::category::FILE_MANAGEMENT, "FILE_MANAGEMENT", "file_mgmt"},
    {w1::abi::api_info::category::STDIO, "STDIO", "stdio"},
    {w1::abi::api_info::category::DEVICE_IO, "DEVICE_IO", "device_io"},
    {w1::abi::api_info::category::PROCESS_CONTROL, "PROCESS_CONTROL", "process"},
    {w1::abi::api_info::category::THREAD_CONTROL, "THREAD_CONTROL", "thread"},
    {w1::abi::api_info::category::THREADING, "THREADING", "threading"},
    {w1::abi::api_info::category::MEMORY_MANAGEMENT, "MEMORY_MANAGEMENT", "memory"},
    {w1::abi::api_info::category::HEAP_MANAGEMENT, "HEAP_MANAGEMENT", "heap"},
    {w1::abi::api_info::category::SYNCHRONIZATION, "SYNCHRONIZATION", "sync"},
    {w1::abi::api_info::category::MUTEX, "MUTEX", "mutex"},
    {w1::abi::api_info::category::EVENT, "EVENT", "event"},
    {w1::abi::api_info::category::SEMAPHORE, "SEMAPHORE", "semaphore"},
    {w1::abi::api_info::category::NETWORK_SOCKET, "NETWORK_SOCKET", "network"},
    {w1::abi::api_info::category::NETWORK_DNS, "NETWORK_DNS", "dns"},
    {w1::abi::api_info::category::NETWORK_HTTP, "NETWORK_HTTP", "http"},
    {w1::abi::api_info::category::REGISTRY, "REGISTRY", "registry"},
    {w1::abi::api_info::category::SECURITY, "SECURITY", "security"},
    {w1::abi::api_info::category::CRYPTO, "CRYPTO", "crypto"},
    {w1::abi::api_info::category::SYSTEM_INFO, "SYSTEM_INFO", "system"},
    {w1::abi::api_info::category::TIME, "TIME", "time"},
    {w1::abi::api_info::category::ENVIRONMENT, "ENVIRONMENT", "environment"},
    {w1::abi::api_info::category::STRING_MANIPULATION, "STRING_MANIPULATION", "string"},
    {w1::abi::api_info::category::LOCALE, "LOCALE", "locale"},
    {w1::abi::api_info::category::LIBRARY_LOADING, "LIBRARY_LOADING", "library"},
    {w1::abi::api_info::category::MATH, "MATH", "math"},
    {w1::abi::api_info::category::SORTING, "SORTING", "sorting"},
    {w1::abi::api_info::category::IPC, "IPC", "ipc"},
    {w1::abi::api_info::category::PIPE, "PIPE", "pipe"},
    {w1::abi::api_info::category::SHARED_MEMORY, "SHARED_MEMORY", "shared_memory"},
    {w1::abi::api_info::category::UI, "UI", "ui"},
    {w1::abi::api_info::category::WINDOW, "WINDOW", "window"},
    {w1::abi::api_info::category::SYSTEM_HOOK, "SYSTEM_HOOK", "system_hook"},
    {w1::abi::api_info::category::MISC, "MISC", "misc"}
};

} // namespace

void setup_api_bindings(
    sol::state& lua,
    sol::table& w1_module,
    runtime::api_manager& api_manager,
    runtime::callback_registry& callback_registry
) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up api bindings");

  sol::table api = lua.create_table();

  api.set_function(
      "register_symbol",
      [&api_manager, &callback_registry](const std::string& module, const std::string& symbol,
                                         sol::protected_function callback) {
        api_manager.register_symbol_callback(module, symbol, std::move(callback));
        callback_registry.ensure_event_enabled(runtime::callback_registry::event_type::exec_transfer_call);
        callback_registry.ensure_event_enabled(runtime::callback_registry::event_type::exec_transfer_return);
      }
  );

  api.set_function(
      "register_module",
      [&api_manager, &callback_registry](const std::string& module, sol::protected_function callback) {
        api_manager.register_module_callback(module, std::move(callback));
        callback_registry.ensure_event_enabled(runtime::callback_registry::event_type::exec_transfer_call);
        callback_registry.ensure_event_enabled(runtime::callback_registry::event_type::exec_transfer_return);
      }
  );

  api.set_function(
      "register_category",
      [&api_manager, &callback_registry](w1::abi::api_info::category category, sol::protected_function callback) {
        api_manager.register_category_callback(category, std::move(callback));
        callback_registry.ensure_event_enabled(runtime::callback_registry::event_type::exec_transfer_call);
        callback_registry.ensure_event_enabled(runtime::callback_registry::event_type::exec_transfer_return);
      }
  );

  api.set_function("category_name", [](w1::abi::api_info::category category) -> std::string {
    for (const auto& cat_info : API_CATEGORIES) {
      if (cat_info.value == category) {
        return cat_info.short_name;
      }
    }
    return "category_" + std::to_string(static_cast<int>(category));
  });

  w1_module["api"] = api;

  sol::table enum_table = w1_module["enum"];
  if (enum_table.valid()) {
    sol::table api_category = lua.create_table();
    for (const auto& cat_info : API_CATEGORIES) {
      api_category[cat_info.enum_name] = cat_info.value;
    }
    enum_table["api_category"] = api_category;
  }
}

} // namespace w1::tracers::script::bindings
