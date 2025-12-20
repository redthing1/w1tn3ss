#include "symbol.hpp"

#include <redlog.hpp>

namespace w1::tracers::script::bindings {

namespace {

sol::table symbol_info_to_lua(sol::state& lua, const w1::symbols::symbol_info& info) {
  sol::table result = lua.create_table();
  result["name"] = info.name;
  result["demangled_name"] = info.demangled_name;
  result["offset"] = info.offset_from_symbol;
  result["module_offset"] = info.module_offset;
  result["size"] = info.size;

  switch (info.symbol_type) {
  case w1::symbols::symbol_info::FUNCTION:
    result["type"] = "function";
    break;
  case w1::symbols::symbol_info::OBJECT:
    result["type"] = "object";
    break;
  case w1::symbols::symbol_info::DEBUG:
    result["type"] = "debug";
    break;
  default:
    result["type"] = "unknown";
    break;
  }

  switch (info.symbol_binding) {
  case w1::symbols::symbol_info::LOCAL:
    result["binding"] = "local";
    break;
  case w1::symbols::symbol_info::GLOBAL:
    result["binding"] = "global";
    break;
  case w1::symbols::symbol_info::WEAK:
    result["binding"] = "weak";
    break;
  default:
    result["binding"] = "unknown";
    break;
  }

  result["is_exported"] = info.is_exported;
  result["is_imported"] = info.is_imported;
  return result;
}

} // namespace

void setup_symbol_bindings(
    sol::state& lua,
    sol::table& w1_module,
    runtime::script_context& context,
    runtime::api_manager& api_manager
) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up symbol bindings");

  sol::table symbol = lua.create_table();

  symbol.set_function("resolve_address", [&lua, &context](uint64_t address) -> sol::object {
    if (address == 0) {
      return sol::lua_nil;
    }

    auto result = context.symbol_resolver().resolve_address(address, context.module_index());
    if (!result) {
      return sol::lua_nil;
    }
    return symbol_info_to_lua(lua, *result);
  });

  symbol.set_function(
      "resolve_name",
      [&lua, &context](const std::string& name, sol::optional<std::string> module_hint) -> sol::object {
        auto result = context.symbol_resolver().resolve_name(name, module_hint.value_or(""));
        if (!result) {
          return sol::lua_nil;
        }
        return sol::make_object(lua, *result);
      }
  );

  symbol.set_function(
      "find",
      [&lua, &context](const std::string& pattern, sol::optional<std::string> module_hint) -> sol::table {
        auto results = context.symbol_resolver().find_symbols(pattern, module_hint.value_or(""));
        sol::table symbols = lua.create_table();
        int index = 1;
        for (const auto& info : results) {
          symbols[index++] = symbol_info_to_lua(lua, info);
        }
        return symbols;
      }
  );

  symbol.set_function("module_symbols", [&lua, &context](const std::string& module_path) -> sol::table {
    auto results = context.symbol_resolver().get_module_symbols(module_path);
    sol::table symbols = lua.create_table();
    int index = 1;
    for (const auto& info : results) {
      symbols[index++] = symbol_info_to_lua(lua, info);
    }
    return symbols;
  });

  symbol.set_function(
      "resolve_in_module", [&lua, &context](const std::string& module_path, uint64_t offset) -> sol::object {
        auto result = context.symbol_resolver().resolve_in_module(module_path, offset);
        if (!result) {
          return sol::lua_nil;
        }
        return symbol_info_to_lua(lua, *result);
      }
  );

  symbol.set_function("backend", [&context]() { return context.symbol_resolver().get_backend_name(); });

  symbol.set_function("clear_cache", [&context]() { context.symbol_resolver().clear_cache(); });

  symbol.set_function("cache_stats", [&lua, &context]() -> sol::table {
    auto stats = context.symbol_resolver().get_cache_stats();
    sol::table table = lua.create_table();
    table["size"] = stats.size;
    table["hits"] = stats.hits;
    table["misses"] = stats.misses;
    table["hit_rate"] = stats.hit_rate;
    return table;
  });

  symbol.set_function("refresh_modules", [&context, &api_manager]() {
    bool refreshed = context.refresh_modules();
    if (refreshed) {
      api_manager.refresh_modules(context.module_index());
    }
    return refreshed;
  });

  w1_module["symbol"] = symbol;
}

} // namespace w1::tracers::script::bindings
