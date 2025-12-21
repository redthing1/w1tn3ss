#include "module.hpp"

namespace w1::tracers::script::bindings {

namespace {

sol::table module_to_lua(sol::state& lua, const w1::runtime::module_info& module) {
  sol::table info = lua.create_table();
  info["name"] = module.name;
  info["path"] = module.path;
  info["base_address"] = module.base_address;
  info["size"] = module.size;
  info["is_system"] = module.is_system;
  info["start"] = module.full_range.start;
  info["end"] = module.full_range.end;
  return info;
}

} // namespace

void setup_module_bindings(sol::state& lua, sol::table& w1_module, runtime::script_context& context) {
  sol::table module = lua.create_table();

  module.set_function("name", [&context](uint64_t address) -> std::string {
    if (address == 0) {
      return "unknown";
    }
    const auto* info = context.modules().find_containing(address);
    return info ? info->name : "unknown";
  });

  module.set_function("info", [&lua, &context](uint64_t address) -> sol::object {
    if (address == 0) {
      return sol::lua_nil;
    }
    const auto* info = context.modules().find_containing(address);
    if (!info) {
      return sol::lua_nil;
    }
    return module_to_lua(lua, *info);
  });

  module.set_function("list", [&lua, &context](sol::optional<std::string> filter) -> sol::table {
    sol::table modules = lua.create_table();
    int index = 1;

    auto list = context.modules().list_modules();
    for (const auto& module_info : list) {
      if (filter.has_value()) {
        const std::string& search = filter.value();
        if (module_info.name.find(search) == std::string::npos && module_info.path.find(search) == std::string::npos) {
          continue;
        }
      }

      modules[index++] = module_to_lua(lua, module_info);
    }

    return modules;
  });

  module.set_function("count", [&context]() {
    auto list = context.modules().list_modules();
    return list.size();
  });

  module.set_function("refresh", [&context]() { return context.refresh_modules(); });

  w1_module["module"] = module;
}

} // namespace w1::tracers::script::bindings
