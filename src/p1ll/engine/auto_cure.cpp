#include "auto_cure.hpp"
#include "core/platform.hpp"
#include "core/context.hpp"
#include "core/signature.hpp"
#include "utils/hex_utils.hpp"
#include "utils/file_utils.hpp"
#include "utils/pretty_hexdump.hpp"
#include "pattern_matcher.hpp"
#include <redlog.hpp>
#include <algorithm>
#include <unordered_set>

namespace p1ll::engine {

auto_cure::auto_cure(const context& ctx) : context_(ctx), scanner_(std::make_unique<memory_scanner>()) {

  auto log = redlog::get_logger("p1ll.auto_cure");
  log.dbg("initialized auto-cure");
}

cure_result auto_cure::execute_dynamic_impl(
    const cure_metadata& meta, const platform_signature_map& signatures, const platform_patch_map& patches
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  log.inf("starting auto-cure", redlog::field("name", meta.name), redlog::field("platforms", meta.platforms.size()));

  // validate platform signatures for dynamic mode
  auto platform_signatures = get_platform_signatures(signatures);
  if (!platform_signatures.empty()) {
    log.inf("validating platform signatures", redlog::field("count", platform_signatures.size()));
    if (!validate_signatures_dynamic(platform_signatures)) {
      cure_result result;
      result.add_error("signature validation failed: cure cannot apply to this platform");
      log.err("signature validation failed");
      return result;
    }
    log.inf("signature validation passed");
  }

  auto platform_patches = get_validated_platform_patches(patches);
  std::vector<std::pair<patch_decl, bool>> patch_results;

  for (const auto& patch : platform_patches) {
    auto compiled_signature_result = compile_patch_decl(patch);
    if (!compiled_signature_result.has_value()) {
      // signature compilation failed
      if (patch.required) {
        cure_result result;
        result.add_error(redlog::fmt("failed to compile required patch signature: %s", patch.signature.pattern));
        log.err("required patch signature compilation failed", redlog::field("signature", patch.signature.pattern));
        return result;
      } else {
        log.wrn(
            "optional patch signature compilation failed, skipping", redlog::field("signature", patch.signature.pattern)
        );
        continue;
      }
    }

    bool patch_success = apply_patch_dynamic(patch, compiled_signature_result.value());
    patch_results.emplace_back(patch, patch_success);
  }

  return process_patch_results(patch_results);
}

cure_result auto_cure::execute_dynamic(const cure_config& config) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  if (!context_.is_dynamic()) {
    cure_result result;
    result.add_error("context is not dynamic: cannot execute dynamic patching");
    log.err("context validation failed: not dynamic");
    return result;
  }

  return execute_dynamic_impl(config.meta, config.signatures, config.patches);
}

cure_result auto_cure::execute_static(std::vector<uint8_t>& buffer_data, const cure_config& config) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  if (context_.is_dynamic()) {
    cure_result result;
    result.add_error("context is dynamic: cannot execute static buffer patching");
    log.err("context validation failed: is dynamic");
    return result;
  }

  return execute_static_impl(buffer_data, config.meta, config.signatures, config.patches);
}

cure_result auto_cure::execute_static_impl(
    std::vector<uint8_t>& buffer_data, const cure_metadata& meta, const platform_signature_map& signatures,
    const platform_patch_map& patches
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  log.inf(
      "starting static buffer auto-cure", redlog::field("name", meta.name),
      redlog::field("buffer_size", buffer_data.size())
  );

  // validate signatures against buffer
  auto platform_signatures = get_platform_signatures(signatures);
  if (!platform_signatures.empty()) {
    log.inf("validating platform signatures against buffer", redlog::field("count", platform_signatures.size()));
    if (!validate_signatures_static(platform_signatures, buffer_data)) {
      cure_result result;
      result.add_error("signature validation failed: cure cannot apply to this buffer");
      log.err("signature validation failed");
      return result;
    }
    log.inf("signature validation passed");
  }

  auto platform_patches = get_validated_platform_patches(patches);
  std::vector<std::pair<patch_decl, bool>> patch_results;

  for (const auto& patch : platform_patches) {
    auto compiled_signature_result = compile_patch_decl(patch);
    if (!compiled_signature_result.has_value()) {
      // signature compilation failed
      if (patch.required) {
        cure_result result;
        result.add_error(redlog::fmt("failed to compile required patch signature: %s", patch.signature.pattern));
        log.err("required patch signature compilation failed", redlog::field("signature", patch.signature.pattern));
        return result;
      } else {
        log.wrn(
            "optional patch signature compilation failed, skipping", redlog::field("signature", patch.signature.pattern)
        );
        continue;
      }
    }

    bool patch_success = apply_patch_static(patch, compiled_signature_result.value(), buffer_data);
    patch_results.emplace_back(patch, patch_success);
  }

  return process_patch_results(patch_results);
}

std::vector<patch_decl> auto_cure::get_platform_patches(const platform_patch_map& patches) const {

  auto log = redlog::get_logger("p1ll.auto_cure");

  // get platform hierarchy for matching
  auto& detector = get_platform_detector();
  auto platform_hierarchy = detector.get_platform_hierarchy_for_context(context_);

  log.dbg("checking platform hierarchy", redlog::field("platforms", platform_hierarchy.size()));

  std::vector<patch_decl> platform_patches;

  // collect patches from all matching platform keys
  for (const auto& platform_key : platform_hierarchy) {
    log.dbg("checking platform for patches", redlog::field("platform", platform_key));

    auto it = patches.find(platform_key);
    if (it != patches.end() && !it->second.empty()) {
      log.dbg(
          "found patches for platform", redlog::field("platform", platform_key),
          redlog::field("count", it->second.size())
      );

      // add all patches from this platform
      for (const auto& patch : it->second) {
        platform_patches.push_back(patch);
      }
    }
  }

  log.dbg("collected platform patches", redlog::field("total", platform_patches.size()));
  return platform_patches;
}

std::vector<signature_decl> auto_cure::get_platform_signatures(const platform_signature_map& signatures) const {
  auto log = redlog::get_logger("p1ll.auto_cure");

  // get effective platform (respects override if set)
  auto& detector = get_platform_detector();
  auto current_platform = detector.get_effective_platform(context_);

  // get platform hierarchy (exact -> os wildcard -> universal)
  auto platform_hierarchy = detector.get_platform_hierarchy(current_platform);

  std::vector<signature_decl> platform_signatures;

  // collect signatures from all matching platform keys
  for (const auto& platform_key : platform_hierarchy) {
    log.dbg("checking platform for signatures", redlog::field("platform", platform_key));

    auto it = signatures.find(platform_key);
    if (it != signatures.end() && !it->second.empty()) {
      log.dbg(
          "found signatures for platform", redlog::field("platform", platform_key),
          redlog::field("count", it->second.size())
      );

      // add all signatures from this platform
      for (const auto& sig : it->second) {
        platform_signatures.push_back(sig);
      }
    }
  }

  // deduplicate signatures by pattern to avoid redundant validation
  std::unordered_set<std::string> seen_patterns;
  std::vector<signature_decl> deduplicated_signatures;

  for (const auto& sig : platform_signatures) {
    if (seen_patterns.find(sig.pattern) == seen_patterns.end()) {
      seen_patterns.insert(sig.pattern);
      deduplicated_signatures.push_back(sig);
    }
  }

  if (deduplicated_signatures.size() != platform_signatures.size()) {
    log.dbg(
        "deduplicated signatures", redlog::field("original", platform_signatures.size()),
        redlog::field("deduplicated", deduplicated_signatures.size())
    );
  }

  log.dbg("collected platform signatures", redlog::field("total", deduplicated_signatures.size()));
  return deduplicated_signatures;
}

bool auto_cure::validate_signatures_dynamic(const std::vector<signature_decl>& signatures) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  for (size_t i = 0; i < signatures.size(); ++i) {
    const auto& sig_obj = signatures[i];

    auto compiled_sig = compile_sig_decl(sig_obj);
    if (!compiled_sig) {
      return false;
    }

    // validate signature exists in memory using the signature's filter if available
    signature_query query;
    query.signature = *compiled_sig;
    query.filter = sig_obj.filter.value_or(signature_query_filter{});

    auto search_results = scanner_->search(query);
    if (!search_results || search_results->empty()) {
      log.wrn("signature not found in memory during validation", redlog::field("pattern", sig_obj.pattern));
      // note: don't fail validation since signature might be optional
    } else {
      // check single match constraint during validation
      if (!validate_single_signature_constraint(sig_obj, search_results->size(), "in memory")) {
        // log all match locations for debugging
        for (size_t j = 0; j < search_results->size(); ++j) {
          log.dbg(
              "match location", redlog::field("index", j + 1), redlog::field("address", (*search_results)[j].address)
          );
        }
        return false;
      }
    }
  }

  log.dbg("signature validation passed", redlog::field("count", signatures.size()));
  return true;
}

bool auto_cure::validate_signatures_static(
    const std::vector<signature_decl>& signatures, const std::vector<uint8_t>& buffer_data
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  for (size_t i = 0; i < signatures.size(); ++i) {
    const auto& sig_obj = signatures[i];

    auto compiled_sig = compile_sig_decl(sig_obj);
    if (!compiled_sig) {
      return false;
    }

    // search for signature in buffer data
    pattern_matcher matcher(*compiled_sig);
    auto offsets = matcher.search_file(buffer_data);

    if (offsets.empty()) {
      log.wrn("signature not found in buffer during validation", redlog::field("pattern", sig_obj.pattern));
      // note: don't fail validation since signature might be optional
    } else {
      // check single match constraint during validation
      if (!validate_single_signature_constraint(sig_obj, offsets.size(), "in buffer")) {
        // log all match locations for debugging
        for (size_t j = 0; j < offsets.size(); ++j) {
          log.dbg(
              "match location", redlog::field("index", j + 1),
              redlog::field("offset", utils::format_address(offsets[j]))
          );
        }
        return false;
      }
    }
  }

  log.dbg("static signature validation passed", redlog::field("count", signatures.size()));
  return true;
}

bool auto_cure::apply_patch_dynamic(const patch_decl& patch, const compiled_signature& signature) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  // search for signature across memory regions
  signature_query query;
  query.signature = signature;
  query.filter = patch.signature.filter.value_or(signature_query_filter{});

  auto search_results_result = scanner_->search(query);
  if (!search_results_result) {
    log.wrn("search failed", redlog::field("signature", patch.signature));
    return false;
  }
  auto search_results = *search_results_result;
  if (search_results.empty()) {
    log.wrn("signature not found", redlog::field("signature", patch.signature));
    return false;
  }

  // check single match enforcement
  if (!validate_single_signature_constraint(patch.signature, search_results.size(), "in memory")) {
    // log all match locations for debugging
    for (size_t i = 0; i < search_results.size(); ++i) {
      log.dbg("match location", redlog::field("index", i + 1), redlog::field("address", search_results[i].address));
    }
    return false;
  }

  // compile patch data once for all applications
  auto compiled_patch_opt = compile_patch(patch.pattern);
  if (!compiled_patch_opt) {
    log.err("failed to compile patch pattern", redlog::field("pattern", patch.pattern));
    return false;
  }

  auto compiled_patch = *compiled_patch_opt;
  auto patch_bytes = extract_patch_bytes(compiled_patch);

  bool any_success = false;
  size_t patch_count = patch.signature.single ? 1 : search_results.size();

  log.dbg(
      patch.signature.single ? "applying patch to single match" : "applying patch to all matches",
      redlog::field("count", patch_count)
  );

  for (size_t i = 0; i < patch_count; ++i) {
    auto& result = search_results[i];
    uint64_t patch_address = result.address + patch.offset;

    log.dbg("applying patch to match", redlog::field("index", i), redlog::field("address", patch_address));

    bool patch_success = apply_single_patch_to_address(patch, patch_bytes, patch_address);
    if (patch_success) {
      any_success = true;
    }
  }

  return any_success;
}

bool auto_cure::apply_patch_static(
    const patch_decl& patch, const compiled_signature& signature, std::vector<uint8_t>& file_data
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  // search for signature in file data
  pattern_matcher matcher(signature);
  size_t patch_offset;

  if (patch.signature.single) {
    // use single match enforcement
    try {
      auto single_offset = matcher.search_single(file_data.data(), file_data.size());
      patch_offset = single_offset + patch.offset;
      log.dbg(
          "single match found for signature", redlog::field("signature", patch.signature),
          redlog::field("offset", single_offset)
      );
    } catch (const std::runtime_error& e) {
      log.err(
          "single match enforcement failed", redlog::field("signature", patch.signature),
          redlog::field("error", e.what())
      );
      return false;
    }
  } else {
    // use normal search (first match)
    auto offsets = matcher.search_file(file_data);
    if (offsets.empty()) {
      log.wrn("signature not found in file", redlog::field("signature", patch.signature));
      return false;
    }
    patch_offset = offsets[0] + patch.offset;
  }

  // compile patch data
  auto compiled_patch_opt = compile_patch(patch.pattern);
  if (!compiled_patch_opt) {
    log.err("failed to compile patch pattern", redlog::field("pattern", patch.pattern));
    return false;
  }

  auto compiled_patch = *compiled_patch_opt;

  // check bounds
  if (patch_offset + compiled_patch.data.size() > file_data.size()) {
    log.err(
        "patch would exceed file bounds", redlog::field("offset", patch_offset),
        redlog::field("patch_size", compiled_patch.data.size()), redlog::field("file_size", file_data.size())
    );
    return false;
  }

  // calculate aligned boundaries for context
  size_t patch_size = compiled_patch.data.size();
  size_t aligned_start = patch_offset & ~0xF;
  size_t aligned_end = std::min(file_data.size(), ((patch_offset + patch_size + 15) & ~0xF));

  // backup original context (aligned)
  std::vector<uint8_t> original_context(file_data.begin() + aligned_start, file_data.begin() + aligned_end);

  // apply patch bytes (respecting mask)
  size_t bytes_patched = 0;
  for (size_t i = 0; i < compiled_patch.data.size(); ++i) {
    if (compiled_patch.mask[i]) { // only write bytes marked in mask
      file_data[patch_offset + i] = compiled_patch.data[i];
      bytes_patched++;
    }
  }

  // get modified context (aligned)
  std::vector<uint8_t> patched_context(file_data.begin() + aligned_start, file_data.begin() + aligned_end);

  log.trc(
      "applying static patch", redlog::field("signature", patch.signature),
      redlog::field("offset", utils::format_address(patch_offset))
  );

  // show beautiful patch hexdump
  if (redlog::get_level() <= redlog::level::debug) {
    // pass aligned context with the aligned start as base offset
    std::string patch_hexdump = utils::format_patch_hexdump(original_context, patched_context, aligned_start);
    log.vrb(redlog::fmt("patch\n%s", patch_hexdump));
  }

  log.dbg(
      "applied static patch", redlog::field("signature", patch.signature), redlog::field("offset", patch_offset),
      redlog::field("bytes", bytes_patched)
  );

  return true;
}

std::vector<patch_decl> auto_cure::get_validated_platform_patches(const platform_patch_map& patches) {
  auto log = redlog::get_logger("p1ll.auto_cure");
  auto platform_patches = get_platform_patches(patches);

  if (platform_patches.empty()) {
    log.err("no patches for current platform");
  } else {
    log.inf("found platform patches", redlog::field("count", platform_patches.size()));
  }

  return platform_patches;
}

cure_result auto_cure::process_patch_results(const std::vector<std::pair<patch_decl, bool>>& patch_results) {
  auto log = redlog::get_logger("p1ll.auto_cure");
  cure_result result;

  for (const auto& [patch, success] : patch_results) {
    if (success) {
      result.patches_applied++;
      log.inf(
          "applied patch", redlog::field("signature", patch.signature.pattern), redlog::field("offset", patch.offset)
      );
    } else {
      result.patches_failed++;
      if (patch.required) {
        result.add_error(redlog::fmt("required patch failed: %s", patch.signature.pattern));
        log.err("required patch failed", redlog::field("signature", patch.signature.pattern));
        return result;
      } else {
        log.wrn("optional patch failed", redlog::field("signature", patch.signature.pattern));
      }
    }
  }

  result.success = (result.patches_failed == 0 || result.patches_applied > 0);
  log.inf(
      "auto-cure completed", redlog::field("success", result.success), redlog::field("applied", result.patches_applied),
      redlog::field("failed", result.patches_failed)
  );

  return result;
}

std::optional<compiled_signature> auto_cure::compile_patch_decl(const patch_decl& patch) {
  auto log = redlog::get_logger("p1ll.auto_cure");
  auto compiled_sig = compile_signature(patch.signature.pattern);
  if (!compiled_sig) {
    if (patch.required) {
      log.err("failed to compile signature", redlog::field("signature", patch.signature.pattern));
    } else {
      log.wrn("failed to compile optional signature", redlog::field("signature", patch.signature.pattern));
    }
  }
  return compiled_sig;
}

std::optional<compiled_signature> auto_cure::compile_sig_decl(const signature_decl& sig_obj) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  if (!validate_signature_pattern(sig_obj.pattern)) {
    log.err("invalid signature pattern", redlog::field("pattern", sig_obj.pattern));
    return std::nullopt;
  }

  auto compiled_sig = compile_signature(sig_obj.pattern);
  if (!compiled_sig) {
    log.err("failed to compile signature for validation", redlog::field("pattern", sig_obj.pattern));
    return std::nullopt;
  }

  return compiled_sig;
}

bool auto_cure::validate_single_signature_constraint(
    const signature_decl& sig_obj, size_t match_count, const std::string& context_desc
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  if (sig_obj.single && match_count > 1) {
    log.err(
        "signature validation failed: multiple matches found for single signature",
        redlog::field("pattern", sig_obj.pattern), redlog::field("matches", match_count)
    );
    log.err(
        "validation failed: signature marked as 'single' but found multiple matches: the "
        "signature pattern is not unique enough"
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

memory_protection auto_cure::calculate_write_protection(memory_protection current_protection, bool is_executable) {
  if (is_executable) {
    // W^X compliance: remove execute, add write
    return static_cast<memory_protection>(
        (static_cast<int>(current_protection) & ~static_cast<int>(memory_protection::execute)) |
        static_cast<int>(memory_protection::write)
    );
  } else {
    // Just add write permission
    return current_protection | memory_protection::write;
  }
}

std::vector<uint8_t> auto_cure::extract_patch_bytes(const compiled_patch& compiled_patch) {
  std::vector<uint8_t> patch_bytes;
  for (size_t i = 0; i < compiled_patch.data.size(); ++i) {
    if (compiled_patch.mask[i]) {
      patch_bytes.push_back(compiled_patch.data[i]);
    }
  }
  return patch_bytes;
}

bool auto_cure::apply_single_patch_to_address(
    const patch_decl& patch, const std::vector<uint8_t>& patch_bytes, uint64_t patch_address
) {

  auto log = redlog::get_logger("p1ll.auto_cure");

  // get current memory protection for target address
  auto current_region_result = scanner_->get_region_info(patch_address);
  if (!current_region_result) {
    if (patch.required) {
      log.err(
          "failed to get memory region info for required patch", redlog::field("signature", patch.signature.pattern),
          redlog::field("address", patch_address)
      );
      return false;
    } else {
      log.wrn(
          "failed to get memory protection for optional patch, skipping",
          redlog::field("signature", patch.signature.pattern), redlog::field("address", patch_address)
      );
      return true; // optional patch failure is not fatal
    }
  }

  auto current_region = *current_region_result;
  auto current_protection = current_region.protection;

  // prepare memory for patching with w^x compliance
  memory_protection original_protection = current_protection;
  bool is_executable = has_protection(current_protection, memory_protection::execute);
  bool is_writable = has_protection(current_protection, memory_protection::write);
  bool needs_protection_change = !is_writable;

  // step 1: enable write access while respecting w^x policy
  if (needs_protection_change) {
    memory_protection write_protection = calculate_write_protection(current_protection, is_executable);

    log.dbg(
        "changing memory protection for patching", redlog::field("address", patch_address),
        redlog::field("original", static_cast<int>(original_protection)),
        redlog::field("temp", static_cast<int>(write_protection)), redlog::field("w_x_compliant", is_executable)
    );

    auto protect_result = scanner_->set_memory_protection(patch_address, patch_bytes.size(), write_protection);
    if (!protect_result) {
      log.err(
          "failed to change memory protection", redlog::field("signature", patch.signature.pattern),
          redlog::field("address", patch_address)
      );
      return !patch.required;
    }
  }

  // calculate aligned boundaries for context reading
  size_t patch_size = patch_bytes.size();
  uint64_t aligned_start = patch_address & ~0xF;
  uint64_t aligned_end = (patch_address + patch_size + 15) & ~0xF;
  size_t context_size = aligned_end - aligned_start;

  // step 2: try to backup aligned context for better hexdump display
  auto context_result = scanner_->read_memory(aligned_start, context_size);
  std::vector<uint8_t> original_context;
  bool has_context = false;

  if (context_result) {
    original_context = *context_result;
    has_context = true;
  }

  // backup original bytes and apply patch
  auto original_data_result = scanner_->read_memory(patch_address, patch_bytes.size());
  if (!original_data_result) {
    log.err("failed to read original bytes for backup", redlog::field("address", patch_address));
    if (needs_protection_change) {
      scanner_->set_memory_protection(patch_address, patch_bytes.size(), original_protection);
    }
    return !patch.required;
  }

  auto original_bytes = *original_data_result;
  auto write_result = scanner_->write_memory(patch_address, patch_bytes);
  bool patch_success = write_result;

  // step 3: verify patch was applied correctly
  if (patch_success) {
    auto verify_result = scanner_->read_memory(patch_address, patch_bytes.size());
    if (verify_result) {
      auto written_bytes = *verify_result;
      patch_success = std::equal(patch_bytes.begin(), patch_bytes.end(), written_bytes.begin());

      if (patch_success) {
        // show beautiful patch hexdump
        if (redlog::get_level() <= redlog::level::debug) {
          if (has_context) {
            // read the modified context
            auto modified_context_result = scanner_->read_memory(aligned_start, context_size);
            if (modified_context_result) {
              auto modified_context = *modified_context_result;
              std::string patch_hexdump =
                  utils::format_patch_hexdump(original_context, modified_context, aligned_start);
              log.vrb(redlog::fmt("patch\n%s", patch_hexdump));
            } else {
              // fallback to just patch bytes
              std::string patch_hexdump = utils::format_patch_hexdump(original_bytes, written_bytes, patch_address);
              log.vrb(redlog::fmt("patch\n%s", patch_hexdump));
            }
          } else {
            // fallback to just patch bytes
            std::string patch_hexdump = utils::format_patch_hexdump(original_bytes, written_bytes, patch_address);
            log.vrb(redlog::fmt("patch\n%s", patch_hexdump));
          }
        }
      } else {
        log.err("patch verification failed, restoring original bytes", redlog::field("address", patch_address));
        scanner_->write_memory(patch_address, original_bytes);
      }
    }
  } else {
    log.err("failed to write patch", redlog::field("address", patch_address));
    scanner_->write_memory(patch_address, original_bytes);
  }

  // step 4: restore original memory protection
  if (needs_protection_change) {
    auto restore_result = scanner_->set_memory_protection(patch_address, patch_bytes.size(), original_protection);
    if (!restore_result) {
      log.wrn("failed to restore original memory protection", redlog::field("address", patch_address));
    }
  }

  if (patch_success) {
    log.inf(
        "successfully applied dynamic patch", redlog::field("signature", patch.signature.pattern),
        redlog::field("address", patch_address), redlog::field("bytes", patch_bytes.size())
    );
  }

  return patch_success;
}

} // namespace p1ll::engine