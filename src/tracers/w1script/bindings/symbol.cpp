#include "symbol.hpp"

namespace w1::tracers::script::bindings {

namespace {

sol::table symbol_info_to_lua(sol::state& lua, const w1::analysis::symbol_info& info) {
  sol::table result = lua.create_table();
  result["module_name"] = info.module_name;
  result["module_path"] = info.module_path;
  result["name"] = info.symbol_name;
  result["demangled_name"] = info.demangled_name;
  result["address"] = info.address;
  result["module_offset"] = info.module_offset;
  result["symbol_address"] = info.symbol_address;
  result["symbol_offset"] = info.symbol_offset;
  result["offset"] = info.symbol_offset;
  result["is_exported"] = info.is_exported;
  result["is_imported"] = info.is_imported;
  result["has_symbol"] = info.has_symbol;
  return result;
}

} // namespace

void setup_symbol_bindings(sol::state& lua, sol::table& w1_module, runtime::script_context& context) {
  sol::table symbol = lua.create_table();

  symbol.set_function("resolve_address", [&lua, &context](uint64_t address) -> sol::object {
    if (address == 0) {
      return sol::lua_nil;
    }

    auto result = context.symbols().resolve(address);
    if (!result) {
      return sol::lua_nil;
    }
    return symbol_info_to_lua(lua, *result);
  });

  symbol.set_function("backend", []() { return std::string("native"); });

  symbol.set_function("clear_cache", [&context]() { context.symbols().clear_cache(); });
  symbol.set_function("cache_size", [&context]() { return context.symbols().cache_size(); });

  w1_module["symbol"] = symbol;
}

} // namespace w1::tracers::script::bindings
