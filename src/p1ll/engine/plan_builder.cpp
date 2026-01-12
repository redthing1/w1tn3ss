#include "plan_builder.hpp"
#include "engine/pattern.hpp"
#include "engine/scanner.hpp"
#include "utils/hex_utils.hpp"
#include <redlog.hpp>
#include <algorithm>
#include <sstream>
#include <unordered_map>

namespace p1ll::engine {

namespace {

std::string make_scan_key(const std::string& pattern, const scan_options& options) {
  std::ostringstream oss;
  oss << pattern << "|";
  oss << options.filter.name_regex << "|";
  oss << (options.filter.only_executable ? "1" : "0") << "|";
  oss << (options.filter.exclude_system ? "1" : "0") << "|";
  oss << options.filter.min_size << "|";
  oss << (options.filter.min_address ? std::to_string(*options.filter.min_address) : "-") << "|";
  oss << (options.filter.max_address ? std::to_string(*options.filter.max_address) : "-") << "|";
  oss << (options.single ? "1" : "0") << "|";
  oss << options.max_matches;
  return oss.str();
}

} // namespace

plan_builder::plan_builder(const address_space& space, platform::platform_key platform_key)
    : space_(space), platform_(std::move(platform_key)) {}

result<bool> plan_builder::platform_allowed(const std::vector<std::string>& selectors) const {
  auto log = redlog::get_logger("p1ll.plan_builder");
  if (selectors.empty()) {
    if (static_cast<int>(redlog::get_level()) >= static_cast<int>(redlog::level::trace)) {
      log.trc("no platform selectors provided", redlog::field("platform", platform_.to_string()));
    }
    return ok_result(true);
  }
  for (const auto& selector : selectors) {
    auto parsed = platform::parse_platform(selector);
    if (!parsed.ok()) {
      log.err("invalid platform selector", redlog::field("selector", selector));
      return error_result<bool>(parsed.status.code, parsed.status.message);
    }
    if (platform::platform_matches(parsed.value, platform_)) {
      if (static_cast<int>(redlog::get_level()) >= static_cast<int>(redlog::level::trace)) {
        log.trc(
            "platform selector matched", redlog::field("selector", selector),
            redlog::field("platform", platform_.to_string())
        );
      }
      return ok_result(true);
    }
  }
  if (static_cast<int>(redlog::get_level()) >= static_cast<int>(redlog::level::trace)) {
    log.trc("no platform selectors matched", redlog::field("platform", platform_.to_string()));
  }
  return ok_result(false);
}

result<std::vector<plan_entry>> plan_builder::build(const recipe& recipe) {
  auto log = redlog::get_logger("p1ll.plan_builder");
  log.trc(
      "building patch plan", redlog::field("recipe", recipe.name),
      redlog::field("validations", recipe.validations.size()), redlog::field("patches", recipe.patches.size())
  );
  auto recipe_ok = platform_allowed(recipe.platforms);
  if (!recipe_ok.ok()) {
    return error_result<std::vector<plan_entry>>(recipe_ok.status.code, recipe_ok.status.message);
  }
  if (!recipe_ok.value) {
    log.inf("recipe not allowed on this platform", redlog::field("platform", platform_.to_string()));
    return error_result<std::vector<plan_entry>>(error_code::platform_mismatch, "recipe not allowed on this platform");
  }

  scanner scanner(space_);
  std::unordered_map<std::string, pattern> signature_cache;
  std::unordered_map<std::string, result<std::vector<scan_result>>> scan_cache;

  auto compile_signature = [&](const std::string& pattern_str) -> result<pattern> {
    auto it = signature_cache.find(pattern_str);
    if (it != signature_cache.end()) {
      return ok_result(it->second);
    }
    auto parsed = parse_signature(pattern_str);
    if (!parsed.ok()) {
      return error_result<pattern>(parsed.status.code, parsed.status.message);
    }
    signature_cache.emplace(pattern_str, parsed.value);
    return parsed;
  };

  auto scan_signature = [&](const std::string& pattern_str,
                            const scan_options& options) -> result<std::vector<scan_result>> {
    std::string key = make_scan_key(pattern_str, options);
    auto it = scan_cache.find(key);
    if (it != scan_cache.end()) {
      return it->second;
    }

    auto compiled = compile_signature(pattern_str);
    if (!compiled.ok()) {
      result<std::vector<scan_result>> err =
          error_result<std::vector<scan_result>>(compiled.status.code, compiled.status.message);
      scan_cache.emplace(key, err);
      return err;
    }

    auto results = scanner.scan(compiled.value, options);
    scan_cache.emplace(key, results);
    return results;
  };

  for (const auto& sig_spec : recipe.validations) {
    auto platform_ok = platform_allowed(sig_spec.platforms);
    if (!platform_ok.ok()) {
      return error_result<std::vector<plan_entry>>(platform_ok.status.code, platform_ok.status.message);
    }
    if (!platform_ok.value) {
      log.trc("skipping validation for platform mismatch", redlog::field("pattern", sig_spec.pattern));
      continue;
    }

    auto scan_results = scan_signature(sig_spec.pattern, sig_spec.options);
    if (!scan_results.ok()) {
      if (sig_spec.required) {
        log.err(
            "validation scan failed", redlog::field("pattern", sig_spec.pattern),
            redlog::field("error", scan_results.status.message)
        );
        return error_result<std::vector<plan_entry>>(
            scan_results.status.code, "validation failed: " + sig_spec.pattern
        );
      }
      log.wrn(
          "optional validation scan failed", redlog::field("pattern", sig_spec.pattern),
          redlog::field("error", scan_results.status.message)
      );
      continue;
    }

    if (scan_results.value.empty() && sig_spec.required) {
      log.err("validation signature not found", redlog::field("pattern", sig_spec.pattern));
      return error_result<std::vector<plan_entry>>(error_code::not_found, "validation not found: " + sig_spec.pattern);
    }
    if (!scan_results.value.empty()) {
      log.dbg(
          "validated signature", redlog::field("pattern", sig_spec.pattern),
          redlog::field("matches", scan_results.value.size())
      );
    }
  }

  std::vector<plan_entry> entries;
  for (const auto& patch_spec : recipe.patches) {
    auto patch_platform_ok = platform_allowed(patch_spec.platforms);
    if (!patch_platform_ok.ok()) {
      return error_result<std::vector<plan_entry>>(patch_platform_ok.status.code, patch_platform_ok.status.message);
    }
    if (!patch_platform_ok.value) {
      log.trc("skipping patch for platform mismatch", redlog::field("pattern", patch_spec.signature.pattern));
      continue;
    }

    auto sig_platform_ok = platform_allowed(patch_spec.signature.platforms);
    if (!sig_platform_ok.ok()) {
      return error_result<std::vector<plan_entry>>(sig_platform_ok.status.code, sig_platform_ok.status.message);
    }
    if (!sig_platform_ok.value) {
      log.trc("skipping signature for platform mismatch", redlog::field("pattern", patch_spec.signature.pattern));
      continue;
    }

    auto scan_results = scan_signature(patch_spec.signature.pattern, patch_spec.signature.options);
    if (!scan_results.ok()) {
      if (patch_spec.required) {
        log.err(
            "patch signature scan failed", redlog::field("pattern", patch_spec.signature.pattern),
            redlog::field("error", scan_results.status.message)
        );
        return error_result<std::vector<plan_entry>>(
            scan_results.status.code, "patch signature failed: " + patch_spec.signature.pattern
        );
      }
      log.wrn(
          "optional patch signature scan failed", redlog::field("pattern", patch_spec.signature.pattern),
          redlog::field("error", scan_results.status.message)
      );
      continue;
    }

    if (scan_results.value.empty()) {
      if (patch_spec.required) {
        log.err("patch signature not found", redlog::field("pattern", patch_spec.signature.pattern));
        return error_result<std::vector<plan_entry>>(
            error_code::not_found, "patch signature not found: " + patch_spec.signature.pattern
        );
      }
      log.wrn("optional patch signature not found", redlog::field("pattern", patch_spec.signature.pattern));
      continue;
    }
    log.dbg(
        "patch signature matched", redlog::field("pattern", patch_spec.signature.pattern),
        redlog::field("matches", scan_results.value.size())
    );

    auto parsed_patch = parse_patch(patch_spec.patch);
    if (!parsed_patch.ok()) {
      if (patch_spec.required) {
        log.err("patch pattern invalid", redlog::field("pattern", patch_spec.patch));
        return error_result<std::vector<plan_entry>>(
            parsed_patch.status.code, "patch pattern invalid: " + patch_spec.patch
        );
      }
      log.wrn("optional patch pattern invalid", redlog::field("pattern", patch_spec.patch));
      continue;
    }

    size_t patch_count = patch_spec.signature.options.single ? 1 : scan_results.value.size();
    for (size_t i = 0; i < patch_count; ++i) {
      const auto& match = scan_results.value[i];
      uint64_t address = match.address;

      if (patch_spec.offset < 0) {
        uint64_t neg = static_cast<uint64_t>(-patch_spec.offset);
        if (address < neg) {
          if (patch_spec.required) {
            log.err("patch offset underflow", redlog::field("pattern", patch_spec.signature.pattern));
            return error_result<std::vector<plan_entry>>(error_code::invalid_argument, "patch offset underflow");
          }
          log.wrn("optional patch offset underflow", redlog::field("pattern", patch_spec.signature.pattern));
          continue;
        }
        address -= neg;
      } else {
        uint64_t add = static_cast<uint64_t>(patch_spec.offset);
        if (address > UINT64_MAX - add) {
          if (patch_spec.required) {
            log.err("patch offset overflow", redlog::field("pattern", patch_spec.signature.pattern));
            return error_result<std::vector<plan_entry>>(error_code::invalid_argument, "patch offset overflow");
          }
          log.wrn("optional patch offset overflow", redlog::field("pattern", patch_spec.signature.pattern));
          continue;
        }
        address += add;
      }

      plan_entry entry;
      entry.spec = patch_spec;
      entry.address = address;
      entry.patch_bytes = parsed_patch.value.bytes;
      entry.patch_mask = parsed_patch.value.mask;
      entries.push_back(std::move(entry));
    }
  }

  if (entries.empty()) {
    log.err("no patch entries produced");
    return error_result<std::vector<plan_entry>>(error_code::not_found, "no patch entries produced");
  }

  std::sort(entries.begin(), entries.end(), [](const plan_entry& a, const plan_entry& b) {
    if (a.address == b.address) {
      return a.patch_bytes.size() < b.patch_bytes.size();
    }
    return a.address < b.address;
  });

  for (size_t i = 1; i < entries.size(); ++i) {
    const auto& prev = entries[i - 1];
    const auto& current = entries[i];
    uint64_t prev_end = prev.address + prev.patch_bytes.size();
    if (prev_end < prev.address) {
      log.err("patch range overflow");
      return error_result<std::vector<plan_entry>>(error_code::invalid_argument, "patch range overflow");
    }
    if (current.address < prev_end) {
      log.err(
          "patches overlap in plan", redlog::field("first", utils::format_address(prev.address)),
          redlog::field("second", utils::format_address(current.address))
      );
      return error_result<std::vector<plan_entry>>(error_code::overlap, "patches overlap in plan");
    }
  }

  log.dbg("built patch plan", redlog::field("entries", entries.size()));
  return ok_result(entries);
}

} // namespace p1ll::engine
