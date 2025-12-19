#pragma once

#include "address_space.hpp"
#include "core/context.hpp"
#include "patch_executor.hpp"
#include <optional>
#include <string>
#include <vector>

namespace p1ll::engine {

class cure_planner {
public:
  cure_planner(const context& ctx, address_space& space);

  std::optional<std::vector<patch_plan_entry>> build_plan(const cure_config& config);
  const std::vector<std::string>& errors() const { return errors_; }

private:
  const context& context_;
  address_space& space_;
  std::vector<std::string> errors_;

  void add_error(const std::string& error);

  bool platform_allowed(const cure_metadata& meta);
  std::vector<signature_decl> collect_platform_signatures(const platform_signature_map& signatures) const;
  std::vector<patch_decl> collect_platform_patches(const platform_patch_map& patches) const;

  bool validate_signatures(const std::vector<signature_decl>& signatures);
  std::optional<compiled_signature> compile_signature_decl(const signature_decl& sig_obj);
  std::optional<compiled_signature> compile_patch_signature(const patch_decl& patch);
  std::optional<compiled_patch> compile_patch_bytes(const patch_decl& patch);

  bool validate_single_signature_constraint(
      const signature_decl& sig_obj, size_t match_count, const std::string& context_desc
  );
};

} // namespace p1ll::engine
