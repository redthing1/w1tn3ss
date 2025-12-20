#include "lua_runtime.hpp"

#include "../bindings/w1_bindings.hpp"

#include <filesystem>

namespace w1::tracers::script::runtime {

lua_runtime::lua_runtime(script_context& context)
    : context_(context),
      api_manager_(),
      callback_registry_(context, api_manager_),
      logger_(redlog::get_logger("w1.script_runtime")) {}

bool lua_runtime::initialize() {
  if (!open_libraries()) {
    return false;
  }

  api_manager_.set_lua_state(lua_.lua_state());
  api_manager_.initialize(context_.module_index(), &context_.symbol_resolver());

  configure_package_paths();

  if (!register_bindings()) {
    return false;
  }

  if (!load_script()) {
    return false;
  }

  if (!call_init()) {
    return false;
  }

  return true;
}

void lua_runtime::shutdown() {
  if (script_table_.valid()) {
    sol::optional<sol::function> shutdown_fn = script_table_["shutdown"];
    if (shutdown_fn) {
      auto result = shutdown_fn.value()();
      if (!result.valid()) {
        sol::error err = result;
        logger_.err("error in script shutdown", redlog::field("error", err.what()));
      }
    }
  }

  context_.shutdown();
  api_manager_.shutdown();
  callback_registry_.shutdown();
  vm_callback_store_.clear();
}

QBDI::VMAction lua_runtime::dispatch_vm_start(QBDI::VMInstanceRef vm) {
  return callback_registry_.dispatch_vm_start(vm);
}

bool lua_runtime::open_libraries() {
  lua_.open_libraries(
      sol::lib::base, sol::lib::package, sol::lib::table, sol::lib::string, sol::lib::math, sol::lib::bit32,
      sol::lib::io, sol::lib::os
  );

  sol::table bit32 = lua_["bit32"];
  if (bit32.valid()) {
    lua_["bit"] = bit32;
    sol::table package = lua_["package"];
    if (package.valid()) {
      sol::table preload = package["preload"];
      if (preload.valid()) {
        preload.set_function("bit", [bit32]() -> sol::table { return bit32; });
      }
    }
  }

  return true;
}

void lua_runtime::configure_package_paths() {
  if (context_.cfg().script_path.empty()) {
    return;
  }

  std::filesystem::path script_path(context_.cfg().script_path);
  auto script_dir = script_path.parent_path();
  if (script_dir.empty()) {
    return;
  }

  std::string path_entry = script_dir.string();
  if (path_entry.empty()) {
    return;
  }

  sol::table package = lua_["package"];
  if (!package.valid()) {
    return;
  }

  std::string lua_path = package["path"].get_or(std::string{});
  std::string lua_cpath = package["cpath"].get_or(std::string{});

  std::string add_path = path_entry + "/?.lua;" + path_entry + "/?/init.lua";
  if (!lua_path.empty()) {
    lua_path += ";";
  }
  lua_path += add_path;
  package["path"] = lua_path;

#if defined(_WIN32)
  std::string so_ext = ".dll";
#elif defined(__APPLE__)
  std::string so_ext = ".dylib";
#else
  std::string so_ext = ".so";
#endif

  std::string add_cpath = path_entry + "/?" + so_ext;
  if (!lua_cpath.empty()) {
    lua_cpath += ";";
  }
  lua_cpath += add_cpath;
  package["cpath"] = lua_cpath;
}

bool lua_runtime::register_bindings() {
  return bindings::setup_w1_bindings(lua_, context_, callback_registry_, api_manager_, vm_callback_store_);
}

bool lua_runtime::load_script() {
  if (context_.cfg().script_path.empty()) {
    logger_.err("script path is empty");
    return false;
  }

  sol::load_result script = lua_.load_file(context_.cfg().script_path);
  if (!script.valid()) {
    sol::error err = script;
    logger_.err("failed to load script", redlog::field("error", err.what()));
    return false;
  }

  sol::protected_function_result exec_result = script();
  if (!exec_result.valid()) {
    sol::error err = exec_result;
    logger_.err("failed to execute script", redlog::field("error", err.what()));
    return false;
  }

  if (exec_result.return_count() == 0 || exec_result.get_type() == sol::type::nil) {
    script_table_ = lua_.create_table();
    return true;
  }

  if (exec_result.get_type() != sol::type::table) {
    logger_.err("script must return a table or nil");
    return false;
  }

  script_table_ = exec_result;
  return true;
}

bool lua_runtime::call_init() {
  if (!script_table_.valid()) {
    return true;
  }

  sol::optional<sol::function> init_fn = script_table_["init"];
  if (!init_fn) {
    return true;
  }

  auto result = init_fn.value()();
  if (!result.valid()) {
    sol::error err = result;
    logger_.err("error in script init", redlog::field("error", err.what()));
    return false;
  }

  return true;
}

} // namespace w1::tracers::script::runtime
