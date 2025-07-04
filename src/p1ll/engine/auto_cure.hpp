#pragma once

#include "../core/types.hpp"
#include "memory_scanner.hpp"
#include <memory>

namespace p1ll::engine {

// declarative auto-cure orchestration engine
class auto_cure_engine {
public:
  auto_cure_engine();
  ~auto_cure_engine() = default;

  // execute auto-cure with separate components
  core::cure_result execute(
      const core::cure_metadata& meta, const core::platform_signature_map& signatures,
      const core::platform_patch_map& patches
  );

  // execute auto-cure with single config
  core::cure_result execute(const core::cure_config& config);

  // static file patching version
  core::cure_result execute_static(
      const std::string& file_path, const std::string& output_path, const core::cure_config& config
  );

  // static buffer patching version (modern api)
  core::cure_result execute_static_buffer(std::vector<uint8_t>& buffer_data, const core::cure_config& config);

private:
  std::unique_ptr<memory_scanner> scanner_;

  // get patches for current platform using hierarchy
  std::vector<core::patch_declaration> get_platform_patches(const core::platform_patch_map& patches) const;

  // get signatures for current platform using hierarchy
  std::vector<core::signature_object> get_platform_signatures(const core::platform_signature_map& signatures) const;

  // validate all required signatures exist before applying patches (dynamic mode)
  bool validate_signatures(const std::vector<core::signature_object>& signatures);

  // validate signatures exist in static buffer (static mode)
  bool validate_signatures(
      const std::vector<core::signature_object>& signatures, const std::vector<uint8_t>& buffer_data
  );

  // apply single patch in memory (dynamic mode)
  bool apply_patch_dynamic(const core::patch_declaration& patch, const core::compiled_signature& signature);

  // apply single patch to file data (static mode)
  bool apply_patch_static(
      const core::patch_declaration& patch, const core::compiled_signature& signature, std::vector<uint8_t>& file_data
  );

  // helper methods for reducing code duplication
  core::cure_result validate_and_prepare_patches(
      const core::cure_metadata& meta, const core::platform_signature_map& signatures,
      const core::platform_patch_map& patches
  );

  std::optional<core::compiled_signature> compile_and_validate_signature(const core::patch_declaration& patch);

  memory_protection calculate_write_protection(memory_protection current_protection, bool is_executable);

  bool apply_single_patch_to_address(
      const core::patch_declaration& patch, const std::vector<uint8_t>& patch_bytes, uint64_t patch_address
  );

  std::vector<uint8_t> extract_patch_bytes(const core::compiled_patch& compiled_patch);
};

} // namespace p1ll::engine