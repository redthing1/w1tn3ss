#include "module_analysis.hpp"
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <redlog.hpp>
#include <memory>

namespace w1::tracers::script::bindings {

// singleton-style module scanner and index for lua access
static std::unique_ptr<w1::util::module_scanner> g_scanner;
static std::unique_ptr<w1::util::module_range_index> g_index;
static bool g_modules_initialized = false;

// ensure module system is initialized
static void ensure_modules_initialized() {
  if (g_modules_initialized) {
    return;
  }

  // create scanner and index
  g_scanner = std::make_unique<w1::util::module_scanner>();
  g_index = std::make_unique<w1::util::module_range_index>();

  // scan modules and build index
  auto modules = g_scanner->scan_executable_modules();
  g_index->rebuild_from_modules(std::move(modules));

  g_modules_initialized = true;

  auto log = redlog::get_logger("w1.script_lua");
  log.dbg("module analysis system initialized with " + std::to_string(g_index->size()) + " modules");
}

// convert module_type enum to string
static std::string module_type_to_string(w1::util::module_type type) {
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

void setup_module_analysis(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up module analysis functions");

  // === simple module name lookup ===
  w1_module.set_function("module_get_name", [](uint64_t address) -> std::string {
    ensure_modules_initialized();

    if (address == 0) {
      return "unknown";
    }

    const auto* module = g_index->find_containing(address);
    return module ? module->name : "unknown";
  });

  // === full module info lookup ===
  w1_module.set_function("module_get_info", [&lua](uint64_t address) -> sol::object {
    ensure_modules_initialized();

    if (address == 0) {
      return sol::nil;
    }

    const auto* module = g_index->find_containing(address);
    if (!module) {
      return sol::nil;
    }

    // create lua table with module info
    sol::table info = lua.create_table();
    info["name"] = module->name;
    info["path"] = module->path;
    info["base_address"] = module->base_address;
    info["size"] = module->size;
    info["type"] = module_type_to_string(module->type);
    info["is_system"] = module->is_system_library;

    return info;
  });

  // === list modules with optional filter ===
  w1_module.set_function("module_list", [&lua](sol::optional<std::string> filter) -> sol::table {
    ensure_modules_initialized();

    sol::table modules = lua.create_table();
    int index = 1;

    g_index->visit_all([&](const w1::util::module_info& module) {
      // if filter provided, check if module matches
      if (filter.has_value()) {
        const std::string& search_str = filter.value();
        if (module.name.find(search_str) == std::string::npos && module.path.find(search_str) == std::string::npos) {
          return; // skip non-matching modules
        }
      }

      // add module to results
      sol::table info = lua.create_table();
      info["name"] = module.name;
      info["path"] = module.path;
      info["base_address"] = module.base_address;
      info["size"] = module.size;
      info["type"] = module_type_to_string(module.type);
      info["is_system"] = module.is_system_library;

      modules[index++] = info;
    });

    return modules;
  });

  // === trigger module rescan ===
  w1_module.set_function("module_scan", []() -> bool {
    try {
      if (!g_scanner) {
        g_scanner = std::make_unique<w1::util::module_scanner>();
      }
      if (!g_index) {
        g_index = std::make_unique<w1::util::module_range_index>();
      }

      // scan modules and rebuild index
      auto modules = g_scanner->scan_executable_modules();
      size_t module_count = modules.size();
      g_index->rebuild_from_modules(std::move(modules));
      g_modules_initialized = true;

      auto log = redlog::get_logger("w1.script_lua");
      log.inf("module rescan completed, found " + std::to_string(module_count) + " modules");

      return true;
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_lua");
      log.err("module scan failed: " + std::string(e.what()));
      return false;
    }
  });

  // === get module count ===
  w1_module.set_function("module_count", []() -> size_t {
    ensure_modules_initialized();
    return g_index->size();
  });

  logger.dbg("module analysis functions setup complete");
}

} // namespace w1::tracers::script::bindings