#pragma once

#include "core/types.hpp"
#include "core/context.hpp"
#include "memory_scanner.hpp"
#include <memory>

namespace p1ll::engine {

// auto-cure class constructed with context
class auto_cure {
public:
  explicit auto_cure(const context& ctx);
  ~auto_cure() = default;

  // dynamic process patching
  cure_result execute_dynamic(const cure_config& config);

  // static buffer patching
  cure_result execute_static(std::vector<uint8_t>& buffer_data, const cure_config& config);

private:
  const context& context_;
  std::unique_ptr<memory_scanner> scanner_;

  // internal implementation for dynamic execution
  cure_result execute_dynamic_impl(
      const cure_metadata& meta, const platform_signature_map& signatures, const platform_patch_map& patches
  );

  // internal implementation for static buffer execution
  cure_result execute_static_impl(
      std::vector<uint8_t>& buffer_data, const cure_metadata& meta, const platform_signature_map& signatures,
      const platform_patch_map& patches
  );

  // get patches for current platform using hierarchy
  std::vector<patch_decl> get_platform_patches(const platform_patch_map& patches) const;

  // get signatures for current platform using hierarchy
  std::vector<signature_decl> get_platform_signatures(const platform_signature_map& signatures) const;

  // validate all required signatures exist in memory
  bool validate_signatures_dynamic(const std::vector<signature_decl>& signatures);

  // validate all required signatures exist in buffer
  bool validate_signatures_static(
      const std::vector<signature_decl>& signatures, const std::vector<uint8_t>& buffer_data
  );

  // apply single patch to memory
  bool apply_patch_dynamic(const patch_decl& patch, const compiled_signature& signature);

  // apply single patch to buffer
  bool apply_patch_static(
      const patch_decl& patch, const compiled_signature& signature, std::vector<uint8_t>& file_data
  );

  // platform patch retrieval
  std::vector<patch_decl> get_validated_platform_patches(const platform_patch_map& patches);

  // signature compilation and validation helpers
  std::optional<compiled_signature> compile_patch_decl(const patch_decl& patch);
  std::optional<compiled_signature> compile_sig_decl(const signature_decl& sig_obj);
  bool validate_single_signature_constraint(
      const signature_decl& sig_obj, size_t match_count, const std::string& context_desc
  );

  // shared patch processing
  cure_result process_patch_results(const std::vector<std::pair<patch_decl, bool>>& patch_results);

  bool apply_single_patch_to_address(
      const patch_decl& patch, const std::vector<uint8_t>& patch_bytes, uint64_t patch_address
  );

  std::vector<uint8_t> extract_patch_bytes(const compiled_patch& compiled_patch);
};

} // namespace p1ll::engine