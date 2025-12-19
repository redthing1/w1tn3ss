#include "cure_planner.hpp"
#include "core/platform.hpp"
#include "core/signature.hpp"
#include "signature_scanner.hpp"
#include <redlog.hpp>
#include <unordered_set>

namespace p1ll::engine {

cure_planner::cure_planner(const context& ctx, address_space& space) : context_(ctx), space_(space) {}

void cure_planner::add_error(const std::string& error) { errors_.push_back(error); }

bool cure_planner::platform_allowed(const cure_metadata& meta) {
  if (meta.platforms.empty()) {
    return true;
  }

  auto& detector = get_platform_detector();
  auto current = detector.get_effective_platform(context_);

  bool any_valid = false;
  for (const auto& platform_str : meta.platforms) {
    auto platform_key = detector.parse_platform_key(platform_str);
    if (!detector.is_valid_platform_key(platform_key)) {
      add_error("invalid platform key in metadata: " + platform_str);
      continue;
    }
    any_valid = true;
    if (detector.platform_matches(platform_key, current)) {
      return true;
    }
  }

  if (any_valid) {
    add_error("current platform not listed in metadata");
  }
  return false;
}

std::optional<std::vector<patch_plan_entry>> cure_planner::build_plan(const cure_config& config) {
  auto log = redlog::get_logger("p1ll.cure_planner");
  errors_.clear();

  if (!platform_allowed(config.meta)) {
    return std::nullopt;
  }

  auto signatures = collect_platform_signatures(config.signatures);
  if (!signatures.empty()) {
    if (!validate_signatures(signatures)) {
      return std::nullopt;
    }
  }

  auto patches = collect_platform_patches(config.patches);
  if (patches.empty()) {
    add_error("no patches found for current platform");
    return std::nullopt;
  }

  signature_scanner scanner(space_);
  std::vector<patch_plan_entry> plan_entries;

  for (const auto& patch : patches) {
    auto compiled_signature = compile_patch_signature(patch);
    if (!compiled_signature) {
      if (patch.required) {
        add_error("failed to compile required patch signature: " + patch.signature.pattern);
        return std::nullopt;
      }
      log.wrn("optional patch signature failed to compile", redlog::field("signature", patch.signature.pattern));
      continue;
    }

    auto search_results = scanner.scan(*compiled_signature, patch.signature.filter.value_or(signature_query_filter{}));
    if (!search_results || search_results->empty()) {
      if (patch.required) {
        add_error("required patch signature not found: " + patch.signature.pattern);
        return std::nullopt;
      }
      log.wrn("optional patch signature not found", redlog::field("signature", patch.signature.pattern));
      continue;
    }

    if (!validate_single_signature_constraint(patch.signature, search_results->size(), "in memory")) {
      add_error("single-match constraint failed for patch signature: " + patch.signature.pattern);
      return std::nullopt;
    }

    auto compiled_patch = compile_patch_bytes(patch);
    if (!compiled_patch) {
      if (patch.required) {
        add_error("failed to compile required patch bytes: " + patch.pattern);
        return std::nullopt;
      }
      log.wrn("optional patch bytes failed to compile", redlog::field("pattern", patch.pattern));
      continue;
    }

    size_t patch_count = patch.signature.single ? 1 : search_results->size();
    for (size_t i = 0; i < patch_count; ++i) {
      const auto& match = (*search_results)[i];
      uint64_t address = match.address + patch.offset;
      patch_plan_entry entry;
      entry.decl = patch;
      entry.address = address;
      entry.patch = *compiled_patch;
      entry.description = patch.to_string();
      plan_entries.push_back(entry);
    }
  }

  if (plan_entries.empty()) {
    add_error("no patch entries produced from cure plan");
    return std::nullopt;
  }

  log.dbg("built cure plan", redlog::field("entries", plan_entries.size()));
  return plan_entries;
}

std::vector<signature_decl> cure_planner::collect_platform_signatures(const platform_signature_map& signatures) const {
  auto log = redlog::get_logger("p1ll.cure_planner");
  auto& detector = get_platform_detector();
  auto current_platform = detector.get_effective_platform(context_);
  auto platform_hierarchy = detector.get_platform_hierarchy(current_platform);

  std::vector<signature_decl> platform_signatures;
  for (const auto& platform_key : platform_hierarchy) {
    auto it = signatures.find(platform_key);
    if (it != signatures.end()) {
      platform_signatures.insert(platform_signatures.end(), it->second.begin(), it->second.end());
    }
  }

  std::unordered_set<std::string> seen;
  std::vector<signature_decl> deduped;
  for (const auto& sig : platform_signatures) {
    std::string filter_pattern = sig.filter ? sig.filter->pattern : "";
    std::string key =
        sig.pattern + "|" + filter_pattern + "|" + (sig.single ? "1" : "0");
    if (seen.insert(key).second) {
      deduped.push_back(sig);
    }
  }

  if (deduped.size() != platform_signatures.size()) {
    log.dbg(
        "deduplicated signatures", redlog::field("original", platform_signatures.size()),
        redlog::field("deduplicated", deduped.size())
    );
  }

  return deduped;
}

std::vector<patch_decl> cure_planner::collect_platform_patches(const platform_patch_map& patches) const {
  auto& detector = get_platform_detector();
  auto platform_hierarchy = detector.get_platform_hierarchy_for_context(context_);

  std::vector<patch_decl> platform_patches;
  for (const auto& platform_key : platform_hierarchy) {
    auto it = patches.find(platform_key);
    if (it != patches.end()) {
      platform_patches.insert(platform_patches.end(), it->second.begin(), it->second.end());
    }
  }

  return platform_patches;
}

bool cure_planner::validate_signatures(const std::vector<signature_decl>& signatures) {
  auto log = redlog::get_logger("p1ll.cure_planner");
  signature_scanner scanner(space_);

  for (const auto& sig_obj : signatures) {
    auto compiled_sig = compile_signature_decl(sig_obj);
    if (!compiled_sig) {
      return false;
    }

    auto results = scanner.scan(*compiled_sig, sig_obj.filter.value_or(signature_query_filter{}));
    if (!results) {
      add_error("failed to search for validation signature: " + sig_obj.pattern);
      return false;
    }

    if (results->empty()) {
      add_error("validation signature not found: " + sig_obj.pattern);
      return false;
    }

    if (!validate_single_signature_constraint(sig_obj, results->size(), "in memory")) {
      add_error("validation signature constraint failed: " + sig_obj.pattern);
      return false;
    }

    log.dbg("validated signature", redlog::field("pattern", sig_obj.pattern));
  }

  return true;
}

std::optional<compiled_signature> cure_planner::compile_signature_decl(const signature_decl& sig_obj) {
  if (!validate_signature_pattern(sig_obj.pattern)) {
    add_error("invalid signature pattern: " + sig_obj.pattern);
    return std::nullopt;
  }

  auto compiled_sig = compile_signature(sig_obj.pattern);
  if (!compiled_sig) {
    add_error("failed to compile signature: " + sig_obj.pattern);
    return std::nullopt;
  }

  return compiled_sig;
}

std::optional<compiled_signature> cure_planner::compile_patch_signature(const patch_decl& patch) {
  auto compiled_sig = compile_signature(patch.signature.pattern);
  if (!compiled_sig) {
    add_error("failed to compile patch signature: " + patch.signature.pattern);
    return std::nullopt;
  }
  return compiled_sig;
}

std::optional<compiled_patch> cure_planner::compile_patch_bytes(const patch_decl& patch) {
  auto compiled = compile_patch(patch.pattern);
  if (!compiled) {
    add_error("failed to compile patch bytes: " + patch.pattern);
    return std::nullopt;
  }
  return compiled;
}

bool cure_planner::validate_single_signature_constraint(
    const signature_decl& sig_obj, size_t match_count, const std::string& context_desc
) {
  auto log = redlog::get_logger("p1ll.cure_planner");

  if (sig_obj.single && match_count != 1) {
    log.err(
        "signature validation failed: single signature constraint not met",
        redlog::field("pattern", sig_obj.pattern), redlog::field("matches", match_count)
    );
    return false;
  }

  if (match_count > 0) {
    log.dbg(
        redlog::fmt("signature validated %s", context_desc), redlog::field("pattern", sig_obj.pattern),
        redlog::field("matches", match_count)
    );
  }

  return true;
}

} // namespace p1ll::engine
