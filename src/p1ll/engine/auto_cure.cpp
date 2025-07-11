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

auto_cure_engine::auto_cure_engine() : scanner_(std::make_unique<memory_scanner>()) {

  auto log = redlog::get_logger("p1ll.auto_cure");
  log.dbg("initialized auto-cure engine");
}

core::cure_result auto_cure_engine::execute(
    const core::cure_metadata& meta, const core::platform_signature_map& signatures,
    const core::platform_patch_map& patches
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  // validate and prepare patches
  auto validation_result = validate_and_prepare_patches(meta, signatures, patches);
  if (!validation_result.success) {
    return validation_result;
  }

  core::cure_result result;
  auto platform_patches = get_platform_patches(patches);

  // apply patches in order (each patch contains its own signature)
  for (const auto& patch : platform_patches) {
    auto compiled_signature_result = compile_and_validate_signature(patch);
    if (!compiled_signature_result.has_value()) {
      if (patch.required) {
        result.add_error("failed to compile signature: " + patch.signature.pattern);
        log.err("failed to compile signature", redlog::field("signature", patch.signature.pattern));
        return result;
      } else {
        log.warn("failed to compile optional signature", redlog::field("signature", patch.signature.pattern));
        result.patches_failed++;
        continue;
      }
    }

    bool patch_success = apply_patch_dynamic(patch, compiled_signature_result.value());

    if (patch_success) {
      result.patches_applied++;
      log.inf(
          "applied patch", redlog::field("signature", patch.signature.pattern), redlog::field("offset", patch.offset)
      );
    } else {
      result.patches_failed++;
      if (patch.required) {
        result.add_error("required patch failed: " + patch.signature.pattern);
        log.err("required patch failed", redlog::field("signature", patch.signature.pattern));
        return result;
      } else {
        log.warn("optional patch failed", redlog::field("signature", patch.signature.pattern));
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

core::cure_result auto_cure_engine::execute(const core::cure_config& config) {
  return execute(config.meta, config.signatures, config.patches);
}

core::cure_result auto_cure_engine::execute_static(
    const std::string& file_path, const std::string& output_path, const core::cure_config& config
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  log.inf(
      "starting static auto-cure", redlog::field("name", config.meta.name), redlog::field("input", file_path),
      redlog::field("output", output_path)
  );

  // read input file
  auto file_data_result = p1ll::utils::read_file(file_path);
  if (!file_data_result.has_value()) {
    core::cure_result result;
    result.add_error("failed to read input file: " + file_path);
    return result;
  }
  auto file_data = file_data_result.value();

  // execute static patching on file data
  auto result = execute_static_buffer(file_data, config);
  if (!result.success) {
    return result;
  }

  // write output file
  auto write_result = p1ll::utils::write_file(output_path, file_data);
  if (!write_result) {
    result.add_error("failed to write output file: " + output_path);
    return result;
  }

  log.inf(
      "static auto-cure completed", redlog::field("applied", result.patches_applied),
      redlog::field("failed", result.patches_failed)
  );

  return result;
}

core::cure_result auto_cure_engine::execute_static_buffer(
    std::vector<uint8_t>& buffer_data, const core::cure_config& config
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  core::cure_result result;

  log.inf(
      "starting static buffer auto-cure", redlog::field("name", config.meta.name),
      redlog::field("buffer_size", buffer_data.size())
  );

  // first validate all platform signatures
  auto platform_signatures = get_platform_signatures(config.signatures);
  if (!platform_signatures.empty()) {
    log.inf(
        "validating platform signatures for static buffer cure", redlog::field("count", platform_signatures.size())
    );

    // for static cure, validate signatures exist in the buffer
    if (!validate_signatures(platform_signatures, buffer_data)) {
      result.add_error("signature validation failed - cure cannot apply");
      log.err("signature validation failed");
      return result;
    }

    log.inf("signature validation passed");
  } else {
    log.dbg("no platform signatures to validate");
  }

  // get patches for current platform
  auto platform_patches = get_platform_patches(config.patches);
  if (platform_patches.empty()) {
    result.add_error("no patches found for current platform");
    return result;
  }

  // apply patches to buffer data - each patch contains its own signature
  for (const auto& patch : platform_patches) {
    auto compiled_signature_result = compile_and_validate_signature(patch);
    if (!compiled_signature_result.has_value()) {
      if (patch.required) {
        result.add_error("failed to compile signature: " + patch.signature.pattern);
        return result;
      } else {
        result.patches_failed++;
        continue;
      }
    }

    bool patch_success = apply_patch_static(patch, compiled_signature_result.value(), buffer_data);

    if (patch_success) {
      result.patches_applied++;
    } else {
      result.patches_failed++;
      if (patch.required) {
        result.add_error("required patch failed: " + patch.signature.pattern);
        return result;
      }
    }
  }

  result.success = true;

  log.inf(
      "static buffer auto-cure completed", redlog::field("applied", result.patches_applied),
      redlog::field("failed", result.patches_failed)
  );

  return result;
}

std::vector<core::patch_declaration> auto_cure_engine::get_platform_patches(
    const core::platform_patch_map& patches
) const {

  auto log = redlog::get_logger("p1ll.auto_cure");

  // get platform hierarchy for matching
  auto platform_hierarchy = core::get_current_platform_hierarchy();

  log.dbg("checking platform hierarchy", redlog::field("platforms", platform_hierarchy.size()));

  // try each platform key in hierarchy order
  for (const auto& platform_key : platform_hierarchy) {
    auto it = patches.find(platform_key);
    if (it != patches.end() && !it->second.empty()) {
      log.dbg(
          "found patches for platform", redlog::field("platform", platform_key),
          redlog::field("count", it->second.size())
      );
      return it->second;
    }
  }

  log.warn("no patches found for any platform in hierarchy");
  return {};
}

std::vector<core::signature_object> auto_cure_engine::get_platform_signatures(
    const core::platform_signature_map& signatures
) const {
  auto log = redlog::get_logger("p1ll.auto_cure");

  // get effective platform (respects override if set)
  auto current_platform = core::get_effective_platform();

  // get platform hierarchy (exact -> os wildcard -> universal)
  auto platform_hierarchy = core::get_platform_hierarchy(current_platform);

  std::vector<core::signature_object> platform_signatures;

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
  std::vector<core::signature_object> deduplicated_signatures;

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

bool auto_cure_engine::validate_signatures(const std::vector<core::signature_object>& signatures) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  // validate all signature patterns are valid
  for (size_t i = 0; i < signatures.size(); ++i) {
    const auto& sig_obj = signatures[i];

    // validate signature pattern
    if (!core::validate_signature_pattern(sig_obj.pattern)) {
      log.err("invalid signature pattern", redlog::field("index", i), redlog::field("pattern", sig_obj.pattern));
      return false;
    }
  }

  // validate signatures exist in target memory/file
  for (size_t i = 0; i < signatures.size(); ++i) {
    const auto& sig_obj = signatures[i];

    // compile signature for validation
    auto compiled_sig = core::compile_signature(sig_obj.pattern);
    if (compiled_sig.empty()) {
      log.err(
          "failed to compile signature for validation", redlog::field("index", i),
          redlog::field("pattern", sig_obj.pattern)
      );
      return false;
    }

    // try to find signature in memory (for dynamic mode) or current context
    auto current_context = core::get_current_context();
    if (current_context && current_context->is_dynamic()) {
      // validate signature exists in memory using the signature's filter if available
      core::signature_query query;
      query.signature = compiled_sig;
      query.filter = sig_obj.filter.value_or(core::signature_query_filter{});

      auto search_results = scanner_->search(query);
      if (!search_results || search_results->empty()) {
        log.warn("signature not found in memory during validation", redlog::field("pattern", sig_obj.pattern));
        // note: don't fail validation since signature might be optional
      } else {
        // check single match constraint during validation
        if (sig_obj.single && search_results->size() > 1) {
          log.err(
              "signature validation failed: multiple matches found for single signature",
              redlog::field("pattern", sig_obj.pattern), redlog::field("matches", search_results->size())
          );

          // log all match locations for debugging
          for (size_t j = 0; j < search_results->size(); ++j) {
            log.dbg(
                "match location", redlog::field("index", j + 1), redlog::field("address", (*search_results)[j].address)
            );
          }

          log.err(
              "validation failed: signature marked as 'single' but found multiple matches - this indicates the "
              "signature pattern is not unique enough"
          );
          return false;
        }

        log.dbg(
            "signature validated in memory", redlog::field("pattern", sig_obj.pattern),
            redlog::field("matches", search_results->size())
        );
      }
    }
  }

  log.dbg("signature validation passed", redlog::field("count", signatures.size()));
  return true;
}

bool auto_cure_engine::validate_signatures(
    const std::vector<core::signature_object>& signatures, const std::vector<uint8_t>& buffer_data
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  // validate all signature patterns are valid
  for (size_t i = 0; i < signatures.size(); ++i) {
    const auto& sig_obj = signatures[i];

    // validate signature pattern
    if (!core::validate_signature_pattern(sig_obj.pattern)) {
      log.err("invalid signature pattern", redlog::field("index", i), redlog::field("pattern", sig_obj.pattern));
      return false;
    }
  }

  // validate signatures exist in static buffer
  for (size_t i = 0; i < signatures.size(); ++i) {
    const auto& sig_obj = signatures[i];

    // compile signature for validation
    auto compiled_sig = core::compile_signature(sig_obj.pattern);
    if (compiled_sig.empty()) {
      log.err(
          "failed to compile signature for validation", redlog::field("index", i),
          redlog::field("pattern", sig_obj.pattern)
      );
      return false;
    }

    // search for signature in buffer data
    pattern_matcher matcher(compiled_sig);
    auto offsets = matcher.search_file(buffer_data);

    if (offsets.empty()) {
      log.warn("signature not found in buffer during validation", redlog::field("pattern", sig_obj.pattern));
      // note: don't fail validation since signature might be optional
    } else {
      // check single match constraint during validation
      if (sig_obj.single && offsets.size() > 1) {
        log.err(
            "signature validation failed: multiple matches found for single signature",
            redlog::field("pattern", sig_obj.pattern), redlog::field("matches", offsets.size())
        );

        // log all match locations for debugging
        for (size_t j = 0; j < offsets.size(); ++j) {
          log.dbg(
              "match location", redlog::field("index", j + 1),
              redlog::field("offset", utils::format_address(offsets[j]))
          );
        }

        log.err(
            "validation failed: signature marked as 'single' but found multiple matches - this indicates the signature "
            "pattern is not unique enough"
        );
        return false;
      }

      log.dbg(
          "signature validated in buffer", redlog::field("pattern", sig_obj.pattern),
          redlog::field("matches", offsets.size())
      );
      // log first match for debugging
      if (!offsets.empty()) {
        log.dbg(
            "first signature match", redlog::field("pattern", sig_obj.pattern),
            redlog::field("offset", utils::format_address(offsets[0]))
        );
      }
    }
  }

  log.dbg("signature validation passed", redlog::field("count", signatures.size()));
  return true;
}

bool auto_cure_engine::apply_patch_dynamic(
    const core::patch_declaration& patch, const core::compiled_signature& signature
) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  // search for signature across memory regions
  core::signature_query query;
  query.signature = signature;
  query.filter = patch.signature.filter.value_or(core::signature_query_filter{});

  auto search_results_result = scanner_->search(query);
  if (!search_results_result) {
    log.warn("search failed", redlog::field("signature", patch.signature));
    return false;
  }
  auto search_results = *search_results_result;
  if (search_results.empty()) {
    log.warn("signature not found", redlog::field("signature", patch.signature));
    return false;
  }

  // check single match enforcement
  if (patch.signature.single && search_results.size() > 1) {
    log.err(
        "multiple matches found for single signature", redlog::field("signature", patch.signature),
        redlog::field("matches", search_results.size())
    );

    // log all match locations for debugging
    for (size_t i = 0; i < search_results.size(); ++i) {
      log.dbg("match location", redlog::field("index", i + 1), redlog::field("address", search_results[i].address));
    }

    return false;
  }

  // apply patch based on signature behavior
  // single=true: we have exactly one match, patch it
  // single=false: patch all matches found (default behavior)
  std::vector<size_t> target_indices;

  if (patch.signature.single) {
    // single match mode - we already validated exactly one match exists
    target_indices.push_back(0);
    log.dbg("applying patch to single match");
  } else {
    // default behavior: patch all matches
    for (size_t i = 0; i < search_results.size(); ++i) {
      target_indices.push_back(i);
    }
    log.dbg("applying patch to all matches", redlog::field("count", search_results.size()));
  }

  // compile patch data once for all applications
  auto compiled_patch = core::compile_patch(patch.pattern);
  if (compiled_patch.empty()) {
    log.err("failed to compile patch pattern", redlog::field("pattern", patch.pattern));
    return false;
  }

  // extract bytes to write (only those marked in mask)
  auto patch_bytes = extract_patch_bytes(compiled_patch);

  bool any_success = false;
  for (size_t idx : target_indices) {
    auto& result = search_results[idx];
    uint64_t patch_address = result.address + patch.offset;

    log.dbg("applying patch to match", redlog::field("index", idx), redlog::field("address", patch_address));

    bool patch_success = apply_single_patch_to_address(patch, patch_bytes, patch_address);
    if (patch_success) {
      any_success = true;
    }
  }

  return any_success || !patch.required;
}

bool auto_cure_engine::apply_patch_static(
    const core::patch_declaration& patch, const core::compiled_signature& signature, std::vector<uint8_t>& file_data
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
      log.warn("signature not found in file", redlog::field("signature", patch.signature));
      return false;
    }
    patch_offset = offsets[0] + patch.offset;
  }

  // compile patch data
  auto compiled_patch = core::compile_patch(patch.pattern);
  if (compiled_patch.empty()) {
    log.err("failed to compile patch pattern", redlog::field("pattern", patch.pattern));
    return false;
  }

  // check bounds
  if (patch_offset + compiled_patch.size() > file_data.size()) {
    log.err(
        "patch would exceed file bounds", redlog::field("offset", patch_offset),
        redlog::field("patch_size", compiled_patch.size()), redlog::field("file_size", file_data.size())
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

  // show beautiful patch hexdump at debug level
  if (redlog::get_level() <= redlog::level::debug) {
    // pass aligned context with the aligned start as base offset
    std::string patch_hexdump = utils::format_patch_hexdump(original_context, patched_context, aligned_start);
    log.dbg(
        "patch hexdump", redlog::field("offset", utils::format_address(patch_offset)),
        redlog::field("size", compiled_patch.data.size())
    );
    // output the hexdump directly to stderr to preserve formatting
    if (!patch_hexdump.empty()) {
      std::fprintf(stderr, "%s", patch_hexdump.c_str());
    }
  }

  log.dbg(
      "applied static patch", redlog::field("signature", patch.signature), redlog::field("offset", patch_offset),
      redlog::field("bytes", bytes_patched)
  );

  return true;
}

core::cure_result auto_cure_engine::validate_and_prepare_patches(
    const core::cure_metadata& meta, const core::platform_signature_map& signatures,
    const core::platform_patch_map& patches
) {

  auto log = redlog::get_logger("p1ll.auto_cure");
  core::cure_result result;

  log.inf("starting auto-cure", redlog::field("name", meta.name), redlog::field("platforms", meta.platforms.size()));

  // validate all platform signatures
  auto platform_signatures = get_platform_signatures(signatures);
  if (!platform_signatures.empty()) {
    log.inf("validating platform signatures", redlog::field("count", platform_signatures.size()));

    if (!validate_signatures(platform_signatures)) {
      result.add_error("signature validation failed - cure cannot apply to this platform");
      log.err("signature validation failed");
      return result;
    }

    log.inf("signature validation passed");
  } else {
    log.dbg("no platform signatures to validate");
  }

  // get patches for current platform
  auto platform_patches = get_platform_patches(patches);
  if (platform_patches.empty()) {
    result.add_error("no patches found for current platform");
    log.err("no patches for current platform");
    return result;
  }

  log.inf("found platform patches", redlog::field("count", platform_patches.size()));
  result.success = true; // validation passed
  return result;
}

std::optional<core::compiled_signature> auto_cure_engine::compile_and_validate_signature(
    const core::patch_declaration& patch
) {
  auto compiled_signature = core::compile_signature(patch.signature.pattern);
  if (compiled_signature.empty()) {
    return std::nullopt;
  }
  return compiled_signature;
}

memory_protection auto_cure_engine::calculate_write_protection(
    memory_protection current_protection, bool is_executable
) {
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

std::vector<uint8_t> auto_cure_engine::extract_patch_bytes(const core::compiled_patch& compiled_patch) {
  std::vector<uint8_t> patch_bytes;
  for (size_t i = 0; i < compiled_patch.data.size(); ++i) {
    if (compiled_patch.mask[i]) {
      patch_bytes.push_back(compiled_patch.data[i]);
    }
  }
  return patch_bytes;
}

bool auto_cure_engine::apply_single_patch_to_address(
    const core::patch_declaration& patch, const std::vector<uint8_t>& patch_bytes, uint64_t patch_address
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
      log.warn(
          "failed to get memory protection for optional patch - skipping",
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
      return patch.required ? false : true;
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
    return patch.required ? false : true;
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
        // show beautiful patch hexdump at debug level
        if (redlog::get_level() <= redlog::level::debug) {
          if (has_context) {
            // read the modified context
            auto modified_context_result = scanner_->read_memory(aligned_start, context_size);
            if (modified_context_result) {
              auto modified_context = *modified_context_result;
              std::string patch_hexdump =
                  utils::format_patch_hexdump(original_context, modified_context, aligned_start);
              log.dbg(
                  "dynamic patch hexdump", redlog::field("address", utils::format_address(patch_address)),
                  redlog::field("size", patch_bytes.size())
              );
              // output the hexdump directly to stderr to preserve formatting
              if (!patch_hexdump.empty()) {
                std::fprintf(stderr, "%s", patch_hexdump.c_str());
              }
            } else {
              // fallback to just patch bytes
              std::string patch_hexdump = utils::format_patch_hexdump(original_bytes, written_bytes, patch_address);
              log.dbg(
                  "dynamic patch hexdump", redlog::field("address", utils::format_address(patch_address)),
                  redlog::field("size", patch_bytes.size())
              );
              if (!patch_hexdump.empty()) {
                std::fprintf(stderr, "%s", patch_hexdump.c_str());
              }
            }
          } else {
            // fallback to just patch bytes
            std::string patch_hexdump = utils::format_patch_hexdump(original_bytes, written_bytes, patch_address);
            log.dbg(
                "dynamic patch hexdump", redlog::field("address", utils::format_address(patch_address)),
                redlog::field("size", patch_bytes.size())
            );
            if (!patch_hexdump.empty()) {
              std::fprintf(stderr, "%s", patch_hexdump.c_str());
            }
          }
        }
      } else {
        log.err("patch verification failed - restoring original bytes", redlog::field("address", patch_address));
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
      log.warn("failed to restore original memory protection", redlog::field("address", patch_address));
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