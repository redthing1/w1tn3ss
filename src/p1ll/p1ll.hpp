#pragma once

#include "core/types.hpp"
#include "core/context.hpp"
#include "engine/auto_cure.hpp"
#include "engine/memory_scanner.hpp"
#include "utils/hex_utils.hpp"
#include <string>
#include <memory>

// main p1ll library interface
namespace p1ll {

// library initialization and configuration
void initialize();
void shutdown();

// auto-cure functions (main API)
core::cure_result auto_cure(
    const core::cure_metadata& meta, const core::platform_signature_map& signatures,
    const core::platform_patch_map& patches
);

core::cure_result auto_cure(const core::cure_config& config);

// static file patching
core::cure_result patch_file(
    const std::string& input_path, const std::string& output_path, const core::cure_config& config
);

// modern buffer-based script execution
core::cure_result execute_static_cure(const std::string& script_content, std::vector<uint8_t>& buffer_data);

core::cure_result execute_dynamic_cure(const std::string& script_content);

// legacy file-based script execution (deprecated)
core::cure_result execute_cure_script(const std::string& script_path);
core::cure_result execute_static_cure(
    const std::string& script_path, const std::string& input_file, const std::string& output_file
);

// manual patching API (for complex cases)
std::vector<core::module_info> get_modules(const core::signature_query_filter& filter = {});

std::vector<core::search_result> search_signature(
    const std::string& signature_pattern, const core::signature_query_filter& filter = {}
);

bool patch_memory(uint64_t address, const std::string& patch_pattern);

// utility functions
std::string str2hex(const std::string& str);
std::string hex2str(const std::string& hex);
std::string format_address(uint64_t address);

// environment configuration for injection mode
struct config {
  std::string cure_script;
  int debug_level = 0;

  static config from_environment();
};

// dynamic entry point for injection
extern "C" void pill_entry();

} // namespace p1ll