#include "symbol_resolution.hpp"
#include <w1tn3ss/symbols/symbol_resolver.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <redlog.hpp>
#include <memory>

namespace w1::tracers::script::bindings {

// singleton symbol resolver instance
static std::unique_ptr<w1::symbols::symbol_resolver> g_symbol_resolver;
static std::unique_ptr<w1::util::module_scanner> g_module_scanner;
static std::unique_ptr<w1::util::module_range_index> g_module_index;
static bool g_symbol_system_initialized = false;

// ensure symbol resolution system is initialized
static void ensure_symbol_system_initialized() {
  if (g_symbol_system_initialized) {
    return;
  }

  auto log = redlog::get_logger("w1.script_symbol");
  log.dbg("initializing symbol resolution system");

  // create symbol resolver with default config
  w1::symbols::symbol_resolver::config cfg;
  cfg.use_native_backend = true;
  cfg.use_lief_backend = true;
  cfg.max_cache_size = 100;
  g_symbol_resolver = std::make_unique<w1::symbols::symbol_resolver>(cfg);

  // create module scanner and index for address-to-module mapping
  g_module_scanner = std::make_unique<w1::util::module_scanner>();
  g_module_index = std::make_unique<w1::util::module_range_index>();

  // scan modules and build index
  auto modules = g_module_scanner->scan_executable_modules();
  g_module_index->rebuild_from_modules(std::move(modules));

  g_symbol_system_initialized = true;

  log.inf(
      "symbol resolution system initialized", redlog::field("backend", g_symbol_resolver->get_backend_name()),
      redlog::field("modules", g_module_index->size())
  );
}

// convert symbol_info to lua table
static sol::table symbol_info_to_lua(sol::state& lua, const w1::symbols::symbol_info& info) {
  sol::table result = lua.create_table();

  result["name"] = info.name;
  result["demangled_name"] = info.demangled_name;
  result["offset"] = info.offset_from_symbol;
  result["module_offset"] = info.module_offset;
  result["size"] = info.size;

  // convert symbol type
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

  // convert symbol binding
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

void setup_symbol_resolution(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up symbol resolution functions");

  // === resolve address to symbol ===
  w1_module.set_function("symbol_resolve_address", [&lua](uint64_t address) -> sol::object {
    ensure_symbol_system_initialized();

    if (address == 0) {
      return sol::nil;
    }

    auto result = g_symbol_resolver->resolve_address(address, *g_module_index);
    if (!result) {
      return sol::nil;
    }

    return symbol_info_to_lua(lua, *result);
  });

  // === resolve symbol name to address ===
  w1_module.set_function(
      "symbol_resolve_name", [&lua](const std::string& name, sol::optional<std::string> module_hint) -> sol::object {
        ensure_symbol_system_initialized();

        std::string hint = module_hint.value_or("");
        auto result = g_symbol_resolver->resolve_name(name, hint);

        if (!result) {
          return sol::nil;
        }

        return sol::make_object(lua, *result);
      }
  );

  // === find symbols by pattern ===
  w1_module.set_function(
      "symbol_find_pattern", [&lua](const std::string& pattern, sol::optional<std::string> module_hint) -> sol::table {
        ensure_symbol_system_initialized();

        std::string hint = module_hint.value_or("");
        auto results = g_symbol_resolver->find_symbols(pattern, hint);

        sol::table symbol_table = lua.create_table();
        int index = 1;
        for (const auto& info : results) {
          symbol_table[index++] = symbol_info_to_lua(lua, info);
        }

        return symbol_table;
      }
  );

  // === get all symbols from a module ===
  w1_module.set_function("symbol_get_module_symbols", [&lua](const std::string& module_path) -> sol::table {
    ensure_symbol_system_initialized();

    auto results = g_symbol_resolver->get_module_symbols(module_path);

    sol::table symbol_table = lua.create_table();
    int index = 1;
    for (const auto& info : results) {
      symbol_table[index++] = symbol_info_to_lua(lua, info);
    }

    return symbol_table;
  });

  // === resolve symbol in specific module ===
  w1_module.set_function(
      "symbol_resolve_in_module", [&lua](const std::string& module_path, uint64_t offset) -> sol::object {
        ensure_symbol_system_initialized();

        auto result = g_symbol_resolver->resolve_in_module(module_path, offset);
        if (!result) {
          return sol::nil;
        }

        return symbol_info_to_lua(lua, *result);
      }
  );

  // === get active backend name ===
  w1_module.set_function("symbol_get_backend", []() -> std::string {
    ensure_symbol_system_initialized();
    return g_symbol_resolver->get_backend_name();
  });

  // === clear symbol cache ===
  w1_module.set_function("symbol_clear_cache", []() {
    ensure_symbol_system_initialized();
    g_symbol_resolver->clear_cache();

    auto log = redlog::get_logger("w1.script_symbol");
    log.dbg("symbol cache cleared");
  });

  // === get cache statistics ===
  w1_module.set_function("symbol_get_cache_stats", [&lua]() -> sol::table {
    ensure_symbol_system_initialized();

    auto stats = g_symbol_resolver->get_cache_stats();

    sol::table stats_table = lua.create_table();
    stats_table["size"] = stats.size;
    stats_table["hits"] = stats.hits;
    stats_table["misses"] = stats.misses;
    stats_table["hit_rate"] = stats.hit_rate;

    return stats_table;
  });

  // === rescan modules (useful after dynamic loading) ===
  w1_module.set_function("symbol_rescan_modules", []() -> bool {
    try {
      if (!g_module_scanner) {
        g_module_scanner = std::make_unique<w1::util::module_scanner>();
      }
      if (!g_module_index) {
        g_module_index = std::make_unique<w1::util::module_range_index>();
      }

      // scan modules and rebuild index
      auto modules = g_module_scanner->scan_executable_modules();
      size_t module_count = modules.size();
      g_module_index->rebuild_from_modules(std::move(modules));

      auto log = redlog::get_logger("w1.script_symbol");
      log.inf("module rescan for symbols completed", redlog::field("modules", module_count));

      return true;
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_symbol");
      log.err("module rescan failed", redlog::field("error", e.what()));
      return false;
    }
  });

  logger.dbg("symbol resolution functions setup complete");
}

} // namespace w1::tracers::script::bindings