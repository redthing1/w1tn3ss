#include "module.hpp"

#include <w1tn3ss/util/module_info.hpp>
#include <redlog.hpp>

namespace w1::tracers::script::bindings {

namespace {

std::string module_type_to_string(w1::util::module_type type) {
  switch (type) {
  case w1::util::module_type::MAIN_EXECUTABLE:
    return "main_executable";
  case w1::util::module_type::SHARED_LIBRARY:
    return "shared_library";
  case w1::util::module_type::ANONYMOUS_EXECUTABLE:
    return "anonymous_executable";
  default:
    return "unknown";
  }
}

sol::table module_to_lua(sol::state& lua, const w1::util::module_info& module) {
  sol::table info = lua.create_table();
  info["name"] = module.name;
  info["path"] = module.path;
  info["base_address"] = module.base_address;
  info["size"] = module.size;
  info["type"] = module_type_to_string(module.type);
  info["is_system"] = module.is_system_library;
  return info;
}

} // namespace

void setup_module_bindings(
    sol::state& lua,
    sol::table& w1_module,
    runtime::script_context& context,
    runtime::api_manager& api_manager
) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up module bindings");

  sol::table module = lua.create_table();

  module.set_function("name", [&context](uint64_t address) -> std::string {
    if (address == 0) {
      return "unknown";
    }
    const auto* info = context.module_index().find_containing(address);
    return info ? info->name : "unknown";
  });

  module.set_function("info", [&lua, &context](uint64_t address) -> sol::object {
    if (address == 0) {
      return sol::lua_nil;
    }
    const auto* info = context.module_index().find_containing(address);
    if (!info) {
      return sol::lua_nil;
    }
    return module_to_lua(lua, *info);
  });

  module.set_function("list", [&lua, &context](sol::optional<std::string> filter) -> sol::table {
    sol::table modules = lua.create_table();
    int index = 1;

    context.module_index().visit_all([&](const w1::util::module_info& module_info) {
      if (filter.has_value()) {
        const std::string& search = filter.value();
        if (module_info.name.find(search) == std::string::npos &&
            module_info.path.find(search) == std::string::npos) {
          return;
        }
      }

      modules[index++] = module_to_lua(lua, module_info);
    });

    return modules;
  });

  module.set_function("count", [&context]() { return context.module_index().size(); });

  module.set_function("refresh", [&context, &api_manager]() {
    bool refreshed = context.refresh_modules();
    if (refreshed) {
      api_manager.refresh_modules(context.module_index());
    }
    return refreshed;
  });

  w1_module["module"] = module;
}

} // namespace w1::tracers::script::bindings
