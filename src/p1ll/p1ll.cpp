#include "p1ll.hpp"
#include "core/platform.hpp"
#include "core/signature.hpp"
#include "scripting/lua_api.hpp"
#include <redlog.hpp>
#include <memory>
#include <cstdlib>
#include <filesystem>

namespace p1ll {

namespace {
std::unique_ptr<engine::auto_cure_engine> g_cure_engine;
std::unique_ptr<engine::memory_scanner> g_scanner;
std::unique_ptr<scripting::lua_api> g_lua_api;
bool g_initialized = false;
} // namespace

void initialize() {
  if (g_initialized) {
    return;
  }

  auto log = redlog::get_logger("p1ll");

  // detect platform
  auto platform = core::get_current_platform();
  log.inf("p1ll initializing", redlog::field("platform", platform.to_string()));

  // initialize engines
  g_cure_engine = std::make_unique<engine::auto_cure_engine>();
  g_scanner = std::make_unique<engine::memory_scanner>();

  g_lua_api = std::make_unique<scripting::lua_api>();
  log.inf("lua scripting support enabled");

  g_initialized = true;
  log.inf("p1ll initialized successfully");
}

void shutdown() {
  if (!g_initialized) {
    return;
  }

  auto log = redlog::get_logger("p1ll");
  log.inf("p1ll shutting down");

  g_cure_engine.reset();
  g_scanner.reset();

  g_lua_api.reset();

  g_initialized = false;
}

core::cure_result auto_cure(
    const core::cure_metadata& meta, const core::platform_signature_map& signatures,
    const core::platform_patch_map& patches
) {
  initialize();
  return g_cure_engine->execute(meta, signatures, patches);
}

core::cure_result auto_cure(const core::cure_config& config) {
  initialize();
  return g_cure_engine->execute(config);
}

core::cure_result patch_file(
    const std::string& input_path, const std::string& output_path, const core::cure_config& config
) {
  initialize();
  return g_cure_engine->execute_static(input_path, output_path, config);
}

core::cure_result execute_cure_script(const std::string& script_path) {
  initialize();
  return g_lua_api->execute_cure_script(script_path);
}

// modern buffer-based script execution
core::cure_result execute_static_cure(const std::string& script_content, std::vector<uint8_t>& buffer_data) {
  initialize();

  auto log = redlog::get_logger("p1ll");
  log.inf(
      "executing static cure with buffer", redlog::field("script_size", script_content.size()),
      redlog::field("buffer_size", buffer_data.size())
  );

  // create static context with buffer reference
  auto context = core::p1ll_context::create_static(buffer_data);
  core::set_current_context(std::move(context));

  // execute lua script
  auto result = g_lua_api->execute_script_content(script_content);

  // clear context
  core::clear_current_context();

  return result;
}

core::cure_result execute_static_cure_with_platform(
    const std::string& script_content, std::vector<uint8_t>& buffer_data, const core::platform_key& platform
) {
  initialize();

  auto log = redlog::get_logger("p1ll");
  log.inf(
      "executing static cure with buffer and platform override", redlog::field("script_size", script_content.size()),
      redlog::field("buffer_size", buffer_data.size()), redlog::field("platform", platform.to_string())
  );

  // create static context with buffer reference and platform override
  auto context = core::p1ll_context::create_static(buffer_data, platform);
  core::set_current_context(std::move(context));

  // execute lua script
  auto result = g_lua_api->execute_script_content(script_content);

  // clear context
  core::clear_current_context();

  return result;
}

core::cure_result execute_dynamic_cure(const std::string& script_content) {
  initialize();

  auto log = redlog::get_logger("p1ll");
  log.inf("executing dynamic cure", redlog::field("script_size", script_content.size()));

  // create dynamic context for live memory patching
  auto context = core::p1ll_context::create_dynamic();
  core::set_current_context(std::move(context));

  // execute lua script
  auto result = g_lua_api->execute_script_content(script_content);

  // clear context
  core::clear_current_context();

  return result;
}

// legacy file-based script execution (deprecated)
core::cure_result execute_static_cure(
    const std::string& script_path, const std::string& input_file, const std::string& output_file
) {
  initialize();
  return g_lua_api->execute_static_cure(script_path, input_file, output_file);
}

std::vector<core::module_info> get_modules(const core::signature_query_filter& filter) {
  initialize();
  auto regions_result = g_scanner->get_memory_regions(filter);
  if (!regions_result) {
    return {};
  }

  // convert regions to module_info format for compatibility
  std::vector<core::module_info> modules;
  for (const auto& region : *regions_result) {
    if (!region.name.empty() && region.is_executable) {
      core::module_info module;
      module.name = std::filesystem::path(region.name).filename().string();
      module.base_address = region.base_address;
      module.size = region.size;
      module.path = region.name;
      modules.push_back(module);
    }
  }
  return modules;
}

std::vector<core::search_result> search_signature(
    const std::string& signature_pattern, const core::signature_query_filter& filter
) {
  initialize();

  auto compiled_sig = core::compile_signature(signature_pattern);
  if (compiled_sig.empty()) {
    return {};
  }

  core::signature_query query;
  query.signature = compiled_sig;
  query.filter = filter;

  auto search_result = g_scanner->search(query);
  if (search_result) {
    return *search_result;
  }
  return {};
}

bool patch_memory(uint64_t address, const std::string& patch_pattern) {
  initialize();

  auto compiled_patch = core::compile_patch(patch_pattern);
  if (compiled_patch.empty()) {
    return false;
  }

  // extract bytes to write (only those marked in mask)
  std::vector<uint8_t> patch_bytes;
  for (size_t i = 0; i < compiled_patch.data.size(); ++i) {
    if (compiled_patch.mask[i]) {
      patch_bytes.push_back(compiled_patch.data[i]);
    }
  }

  return g_scanner->write_memory(address, patch_bytes);
}

std::string str2hex(const std::string& str) { return utils::str2hex(str); }

std::string hex2str(const std::string& hex) { return utils::hex2str(hex); }

std::string format_address(uint64_t address) { return utils::format_address(address); }

config config::from_environment() {
  config cfg;

  // read environment variables
  if (const char* cure_env = std::getenv("PILL_CURE")) {
    cfg.cure_script = cure_env;
  }

  if (const char* debug_env = std::getenv("PILL_DEBUG")) {
    cfg.debug_level = std::atoi(debug_env);
  }

  return cfg;
}

} // namespace p1ll

// dynamic entry point for injection
extern "C" void pill_entry() {
  auto log = redlog::get_logger("p1ll.entry");

  // read configuration from environment
  auto cfg = p1ll::config::from_environment();

  // set debug level if specified
  if (cfg.debug_level > 0) {
    // map debug levels: 1=info, 2=debug, 3=trace, 4=pedantic
    redlog::level log_level = redlog::level::info;
    switch (cfg.debug_level) {
    case 1:
      log_level = redlog::level::info;
      break;
    case 2:
      log_level = redlog::level::debug;
      break;
    case 3:
      log_level = redlog::level::trace;
      break;
    default:
      log_level = redlog::level::debug;
      break;
    }
    redlog::set_level(log_level);
  }

  log.inf(
      "p1ll entry point called", redlog::field("cure_script", cfg.cure_script),
      redlog::field("debug_level", cfg.debug_level)
  );

  if (!cfg.cure_script.empty()) {
    log.inf("executing cure script", redlog::field("script", cfg.cure_script));

    auto result = p1ll::execute_cure_script(cfg.cure_script);

    if (result.success) {
      log.inf(
          "cure script completed successfully", redlog::field("patches_applied", result.patches_applied),
          redlog::field("patches_failed", result.patches_failed)
      );
    } else {
      log.err("cure script failed", redlog::field("errors", result.error_messages.size()));
      for (const auto& error : result.error_messages) {
        log.err("cure error", redlog::field("message", error));
      }
    }
  } else {
    log.inf("no cure script specified, p1ll loaded but inactive");
  }
}