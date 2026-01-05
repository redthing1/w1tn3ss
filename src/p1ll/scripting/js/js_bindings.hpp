#pragma once

#include <jnjs/jnjs.h>
#include <redlog.hpp>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <limits>
#include <optional>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

#include "p1ll/engine/result.hpp"
#include "p1ll/engine/session.hpp"
#include "p1ll/engine/types.hpp"
#include "p1ll/utils/hex_utils.hpp"

namespace p1ll::scripting::js {

using namespace jnjs;

inline const char* error_code_name(engine::error_code code) {
  switch (code) {
  case engine::error_code::ok:
    return "ok";
  case engine::error_code::invalid_argument:
    return "invalid_argument";
  case engine::error_code::invalid_pattern:
    return "invalid_pattern";
  case engine::error_code::not_found:
    return "not_found";
  case engine::error_code::multiple_matches:
    return "multiple_matches";
  case engine::error_code::io_error:
    return "io_error";
  case engine::error_code::protection_error:
    return "protection_error";
  case engine::error_code::verification_failed:
    return "verification_failed";
  case engine::error_code::platform_mismatch:
    return "platform_mismatch";
  case engine::error_code::overlap:
    return "overlap";
  case engine::error_code::unsupported:
    return "unsupported";
  case engine::error_code::invalid_context:
    return "invalid_context";
  case engine::error_code::internal_error:
    return "internal_error";
  }
  return "unknown";
}

inline std::string format_status(const engine::status& status) {
  std::string label = error_code_name(status.code);
  if (status.message.empty()) {
    return label;
  }
  return label + ": " + status.message;
}

inline bool looks_like_path(const std::string& value) {
  return value.find('/') != std::string::npos || value.find('\\') != std::string::npos;
}

inline std::string module_key_for_path(const std::string& path) {
#ifdef _WIN32
  std::string key = path;
  std::replace(key.begin(), key.end(), '/', '\\');
  std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return key;
#else
  return path;
#endif
}

// result wrapper for script-friendly return values
struct apply_report_wrapper {
  bool success = false;
  int applied = 0;
  int failed = 0;
  std::vector<std::string> error_messages;
  std::vector<engine::status> diagnostics;

  apply_report_wrapper() = default;
  apply_report_wrapper(const engine::apply_report& report)
      : success(report.success), applied(static_cast<int>(report.applied)), failed(static_cast<int>(report.failed)) {
    diagnostics = report.diagnostics;
    for (const auto& diag : report.diagnostics) {
      if (!diag.message.empty()) {
        error_messages.push_back(diag.message);
      }
    }
  }

  void add_error(const std::string& message) {
    error_messages.push_back(message);
    diagnostics.push_back(engine::make_status(engine::error_code::invalid_argument, message));
    success = false;
  }

  bool get_success() { return success; }
  int get_applied() { return applied; }
  int get_failed() { return failed; }
  std::vector<std::string> get_error_messages() { return error_messages; }
  std::vector<std::string> get_diagnostics() {
    std::vector<std::string> output;
    output.reserve(diagnostics.size());
    for (const auto& diag : diagnostics) {
      output.push_back(format_status(diag));
    }
    return output;
  }
  std::vector<engine::status> get_statuses() { return diagnostics; }
  bool has_errors() { return !error_messages.empty(); }

  constexpr static wrapped_class_builder<apply_report_wrapper> build_js_class() {
    wrapped_class_builder<apply_report_wrapper> builder("apply_report");
    builder.bind_function<&apply_report_wrapper::get_success>("get_success");
    builder.bind_function<&apply_report_wrapper::get_applied>("get_applied");
    builder.bind_function<&apply_report_wrapper::get_failed>("get_failed");
    builder.bind_function<&apply_report_wrapper::get_error_messages>("get_error_messages");
    builder.bind_function<&apply_report_wrapper::get_diagnostics>("get_diagnostics");
    builder.bind_function<&apply_report_wrapper::has_errors>("has_errors");
    return builder;
  }
};

struct scan_result_wrapper {
  uint64_t address = 0;
  std::string region_name;

  scan_result_wrapper() = default;
  scan_result_wrapper(const engine::scan_result& result) : address(result.address), region_name(result.region_name) {}

  uint64_t get_address() { return address; }
  std::string get_region_name() { return region_name; }

  constexpr static wrapped_class_builder<scan_result_wrapper> build_js_class() {
    wrapped_class_builder<scan_result_wrapper> builder("scan_result");
    builder.bind_function<&scan_result_wrapper::get_address>("get_address");
    builder.bind_function<&scan_result_wrapper::get_region_name>("get_region_name");
    return builder;
  }
};

struct module_info_wrapper {
  std::string name;
  std::string path;
  uint64_t base_address = 0;
  uint64_t size = 0;
  std::string permissions;
  bool is_system_module = false;

  std::string get_name() { return name; }
  std::string get_path() { return path; }
  uint64_t get_base_address() { return base_address; }
  uint64_t get_size() { return size; }
  std::string get_permissions() { return permissions; }
  bool get_is_system_module() { return is_system_module; }

  constexpr static wrapped_class_builder<module_info_wrapper> build_js_class() {
    wrapped_class_builder<module_info_wrapper> builder("module_info");
    builder.bind_function<&module_info_wrapper::get_name>("get_name");
    builder.bind_function<&module_info_wrapper::get_path>("get_path");
    builder.bind_function<&module_info_wrapper::get_base_address>("get_base_address");
    builder.bind_function<&module_info_wrapper::get_size>("get_size");
    builder.bind_function<&module_info_wrapper::get_permissions>("get_permissions");
    builder.bind_function<&module_info_wrapper::get_is_system_module>("get_is_system_module");
    return builder;
  }
};

struct signature_wrapper {
  engine::signature_spec spec;

  signature_wrapper() = default;
  explicit signature_wrapper(engine::signature_spec spec_in) : spec(std::move(spec_in)) {}

  std::string get_pattern() { return spec.pattern; }

  constexpr static wrapped_class_builder<signature_wrapper> build_js_class() {
    wrapped_class_builder<signature_wrapper> builder("signature");
    builder.bind_function<&signature_wrapper::get_pattern>("get_pattern");
    return builder;
  }
};

struct patch_wrapper {
  engine::patch_spec spec;

  patch_wrapper() = default;
  explicit patch_wrapper(engine::patch_spec spec_in) : spec(std::move(spec_in)) {}

  signature_wrapper* get_signature() { return new signature_wrapper(spec.signature); }
  int64_t get_offset() { return spec.offset; }
  std::string get_pattern() { return spec.patch; }
  bool is_required() { return spec.required; }

  constexpr static wrapped_class_builder<patch_wrapper> build_js_class() {
    wrapped_class_builder<patch_wrapper> builder("patch");
    builder.bind_function<&patch_wrapper::get_signature>("get_signature");
    builder.bind_function<&patch_wrapper::get_offset>("get_offset");
    builder.bind_function<&patch_wrapper::get_pattern>("get_pattern");
    builder.bind_function<&patch_wrapper::is_required>("is_required");
    return builder;
  }
};

inline bool is_defined(const jnjs::value& value) { return !(value.is<jnjs::undefined>() || value.is<jnjs::null>()); }

inline std::optional<uint64_t> parse_u64(const jnjs::value& value) {
  if (value.is<uint64_t>()) {
    return value.as<uint64_t>();
  }
  if (value.is<int64_t>()) {
    int64_t v = value.as<int64_t>();
    if (v < 0) {
      return std::nullopt;
    }
    return static_cast<uint64_t>(v);
  }
  if (value.is<int>()) {
    int v = value.as<int>();
    if (v < 0) {
      return std::nullopt;
    }
    return static_cast<uint64_t>(v);
  }
  return std::nullopt;
}

inline void apply_scan_options(engine::scan_options& options, const jnjs::value& obj) {
  auto filter_val = obj["filter"];
  if (filter_val.is<std::string>()) {
    options.filter.name_regex = filter_val.as<std::string>();
  }

  auto single_val = obj["single"];
  if (single_val.is<bool>()) {
    options.single = single_val.as<bool>();
  }

  auto max_val = obj["max_matches"];
  if (max_val.is<int>()) {
    options.max_matches = static_cast<size_t>(max_val.as<int>());
  }

  auto exec_val = obj["only_executable"];
  if (exec_val.is<bool>()) {
    options.filter.only_executable = exec_val.as<bool>();
  }

  auto sys_val = obj["exclude_system"];
  if (sys_val.is<bool>()) {
    options.filter.exclude_system = sys_val.as<bool>();
  }

  auto min_size = obj["min_size"];
  if (min_size.is<int>()) {
    options.filter.min_size = static_cast<size_t>(min_size.as<int>());
  }

  auto min_addr = obj["min_address"];
  if (is_defined(min_addr)) {
    auto parsed = parse_u64(min_addr);
    if (parsed.has_value()) {
      options.filter.min_address = parsed;
    }
  }

  auto max_addr = obj["max_address"];
  if (is_defined(max_addr)) {
    auto parsed = parse_u64(max_addr);
    if (parsed.has_value()) {
      options.filter.max_address = parsed;
    }
  }
}

inline std::vector<std::string> parse_platform_list(const jnjs::value& value) {
  if (value.is<std::vector<std::string>>()) {
    return value.as<std::vector<std::string>>();
  }
  return {};
}

// main api exposed to scripts
struct p1ll_api {
  engine::session* session = nullptr;

  explicit p1ll_api(engine::session* session_in) : session(session_in) {}

  std::string str2hex(const std::string& str) { return p1ll::utils::str2hex(str); }
  std::string hex2str(const std::string& hex) { return p1ll::utils::hex2str(hex); }
  std::string format_address(uint64_t address) { return p1ll::utils::format_address(address); }

  signature_wrapper* sig(const std::string& pattern, std::optional<jnjs::value> options = std::nullopt) {
    engine::signature_spec spec;
    spec.pattern = pattern;

    if (options && is_defined(*options)) {
      apply_scan_options(spec.options, *options);

      auto required_val = (*options)["required"];
      if (required_val.is<bool>()) {
        spec.required = required_val.as<bool>();
      }

      auto platforms_val = (*options)["platforms"];
      if (is_defined(platforms_val)) {
        spec.platforms = parse_platform_list(platforms_val);
      }
    }

    return new signature_wrapper(spec);
  }

  patch_wrapper* patch(
      signature_wrapper* sig, int64_t offset, const std::string& patch_pattern,
      std::optional<jnjs::value> options = std::nullopt
  ) {
    engine::patch_spec spec;
    if (sig) {
      spec.signature = sig->spec;
    }
    spec.offset = offset;
    spec.patch = patch_pattern;
    spec.required = true;

    if (options && is_defined(*options)) {
      auto required_val = (*options)["required"];
      if (required_val.is<bool>()) {
        spec.required = required_val.as<bool>();
      }

      auto platforms_val = (*options)["platforms"];
      if (is_defined(platforms_val)) {
        spec.platforms = parse_platform_list(platforms_val);
      }
    }

    return new patch_wrapper(spec);
  }

  apply_report_wrapper* auto_cure(jnjs::value meta_obj);

  std::vector<module_info_wrapper*> get_modules(const std::string& filter_pattern = "") {
    auto log = redlog::get_logger("p1ll.js");

    if (!session || !session->is_dynamic()) {
      log.dbg("get_modules unavailable in static mode");
      return {};
    }

    auto regions = session->regions(engine::scan_filter{});
    if (!regions.ok()) {
      log.err("get_modules failed", redlog::field("error", regions.status.message));
      return {};
    }

    std::optional<std::regex> filter_regex;
    if (!filter_pattern.empty()) {
      try {
        filter_regex.emplace(filter_pattern);
      } catch (const std::regex_error&) {
        log.err("invalid module filter regex");
        return {};
      }
    }

    struct module_accumulator {
      std::string path;
      uint64_t base_address = std::numeric_limits<uint64_t>::max();
      uint64_t end_address = 0;
      engine::memory_protection protection = engine::memory_protection::none;
      bool has_executable = false;
      bool is_system = false;
    };

    std::unordered_map<std::string, module_accumulator> modules;
    for (const auto& region : regions.value) {
      if (region.name.empty() || !looks_like_path(region.name)) {
        continue;
      }

      auto& entry = modules[module_key_for_path(region.name)];
      if (entry.path.empty()) {
        entry.path = region.name;
      }

      entry.base_address = std::min(entry.base_address, region.base_address);
      uint64_t region_end = region.base_address + region.size;
      if (region_end >= region.base_address) {
        entry.end_address = std::max(entry.end_address, region_end);
      }
      entry.protection = entry.protection | region.protection;
      entry.has_executable = entry.has_executable || region.is_executable;
      entry.is_system = entry.is_system || region.is_system;
    }

    std::vector<module_info_wrapper*> result;
    result.reserve(modules.size());
    for (const auto& [path, entry] : modules) {
      if (!entry.has_executable || entry.base_address == std::numeric_limits<uint64_t>::max()) {
        continue;
      }

      std::string name = std::filesystem::path(entry.path).filename().string();
      if (filter_regex) {
        if (!std::regex_search(entry.path, *filter_regex) && !std::regex_search(name, *filter_regex)) {
          continue;
        }
      }

      if (entry.end_address < entry.base_address) {
        continue;
      }

      auto* mod = new module_info_wrapper();
      mod->name = name;
      mod->path = entry.path;
      mod->base_address = entry.base_address;
      mod->size = entry.end_address - entry.base_address;
      mod->permissions =
          std::string(engine::has_protection(entry.protection, engine::memory_protection::read) ? "r" : "-") +
          (engine::has_protection(entry.protection, engine::memory_protection::write) ? "w" : "-") +
          (engine::has_protection(entry.protection, engine::memory_protection::execute) ? "x" : "-");
      mod->is_system_module = entry.is_system;
      result.push_back(mod);
    }

    std::sort(result.begin(), result.end(), [](const module_info_wrapper* a, const module_info_wrapper* b) {
      return a->base_address < b->base_address;
    });

    log.dbg("found modules", redlog::field("count", result.size()));
    return result;
  }

  std::vector<scan_result_wrapper*> search_sig_multiple(
      const std::string& pattern, std::optional<jnjs::value> options = std::nullopt
  ) {
    auto log = redlog::get_logger("p1ll.js");
    if (!session) {
      log.err("search_sig_multiple called with no session");
      return {};
    }

    engine::scan_options scan_opts;
    if (options && is_defined(*options)) {
      apply_scan_options(scan_opts, *options);
    }

    auto results = session->scan(pattern, scan_opts);
    if (!results.ok()) {
      log.err("search failed", redlog::field("pattern", pattern), redlog::field("error", results.status.message));
      return {};
    }

    std::vector<scan_result_wrapper*> output;
    for (const auto& result : results.value) {
      output.push_back(new scan_result_wrapper(result));
    }
    log.dbg("search completed", redlog::field("results", output.size()));
    return output;
  }

  scan_result_wrapper* search_sig(const std::string& pattern, std::optional<jnjs::value> options = std::nullopt) {
    auto log = redlog::get_logger("p1ll.js");
    if (!session) {
      log.err("search_sig called with no session");
      return nullptr;
    }

    engine::scan_options scan_opts;
    if (options && is_defined(*options)) {
      apply_scan_options(scan_opts, *options);
    }

    auto results = session->scan(pattern, scan_opts);
    if (!results.ok() || results.value.empty()) {
      if (!results.ok()) {
        log.err("search failed", redlog::field("pattern", pattern), redlog::field("error", results.status.message));
      } else {
        log.dbg("search returned no matches", redlog::field("pattern", pattern));
      }
      return nullptr;
    }

    if (scan_opts.single && results.value.size() != 1) {
      log.dbg(
          "single match required but search returned unexpected count", redlog::field("count", results.value.size())
      );
      return nullptr;
    }

    if (results.value.size() > 1) {
      log.wrn("multiple matches, returning first", redlog::field("count", results.value.size()));
    }
    return new scan_result_wrapper(results.value.front());
  }

  void log_info(const std::string& msg) { redlog::get_logger("p1ll.js").inf(msg); }
  void log_debug(const std::string& msg) { redlog::get_logger("p1ll.js").dbg(msg); }
  void log_warn(const std::string& msg) { redlog::get_logger("p1ll.js").wrn(msg); }
  void log_err(const std::string& msg) { redlog::get_logger("p1ll.js").err(msg); }

  constexpr static wrapped_class_builder<p1ll_api> build_js_class() {
    wrapped_class_builder<p1ll_api> builder("p1ll_api");
    builder.bind_function<&p1ll_api::str2hex>("str2hex");
    builder.bind_function<&p1ll_api::hex2str>("hex2str");
    builder.bind_function<&p1ll_api::format_address>("format_address");
    builder.bind_function<&p1ll_api::sig>("sig");
    builder.bind_function<&p1ll_api::patch>("patch");
    builder.bind_function<&p1ll_api::auto_cure>("auto_cure");
    builder.bind_function<&p1ll_api::get_modules>("get_modules");
    builder.bind_function<&p1ll_api::search_sig>("search_sig");
    builder.bind_function<&p1ll_api::search_sig_multiple>("search_sig_multiple");
    builder.bind_function<&p1ll_api::log_info>("log_info");
    builder.bind_function<&p1ll_api::log_debug>("log_debug");
    builder.bind_function<&p1ll_api::log_warn>("log_warn");
    builder.bind_function<&p1ll_api::log_err>("log_err");
    return builder;
  }
};

inline void append_signatures_from_map(
    std::vector<engine::signature_spec>& out,
    const std::unordered_map<std::string, std::vector<signature_wrapper*>>& sigs_map
) {
  for (const auto& [platform_key, sigs] : sigs_map) {
    for (auto* sig : sigs) {
      if (!sig) {
        continue;
      }
      engine::signature_spec spec = sig->spec;
      spec.platforms.clear();
      if (platform_key != "*" && platform_key != "*:*") {
        spec.platforms.push_back(platform_key);
      }
      out.push_back(spec);
    }
  }
}

inline void append_patches_from_map(
    std::vector<engine::patch_spec>& out, const std::unordered_map<std::string, std::vector<patch_wrapper*>>& patch_map
) {
  for (const auto& [platform_key, patches] : patch_map) {
    for (auto* patch : patches) {
      if (!patch) {
        continue;
      }
      engine::patch_spec spec = patch->spec;
      spec.platforms.clear();
      if (platform_key != "*" && platform_key != "*:*") {
        spec.platforms.push_back(platform_key);
      }
      out.push_back(spec);
    }
  }
}

inline engine::recipe parse_recipe(const jnjs::value& meta_obj) {
  engine::recipe recipe;

  auto name_val = meta_obj["name"];
  if (name_val.is<std::string>()) {
    recipe.name = name_val.as<std::string>();
  }

  auto platforms_val = meta_obj["platforms"];
  if (platforms_val.is<std::vector<std::string>>()) {
    recipe.platforms = platforms_val.as<std::vector<std::string>>();
  }

  auto validations_val = meta_obj["validations"];
  if (validations_val.is<std::vector<signature_wrapper*>>()) {
    for (auto* sig : validations_val.as<std::vector<signature_wrapper*>>()) {
      if (sig) {
        recipe.validations.push_back(sig->spec);
      }
    }
  }

  auto sigs_val = meta_obj["sigs"];
  if (sigs_val.is<std::unordered_map<std::string, std::vector<signature_wrapper*>>>()) {
    append_signatures_from_map(
        recipe.validations, sigs_val.as<std::unordered_map<std::string, std::vector<signature_wrapper*>>>()
    );
  }

  auto patches_val = meta_obj["patches"];
  if (patches_val.is<std::vector<patch_wrapper*>>()) {
    for (auto* patch : patches_val.as<std::vector<patch_wrapper*>>()) {
      if (patch) {
        recipe.patches.push_back(patch->spec);
      }
    }
  } else if (patches_val.is<std::unordered_map<std::string, std::vector<patch_wrapper*>>>()) {
    append_patches_from_map(
        recipe.patches, patches_val.as<std::unordered_map<std::string, std::vector<patch_wrapper*>>>()
    );
  }

  return recipe;
}

inline apply_report_wrapper* p1ll_api::auto_cure(jnjs::value meta_obj) {
  auto log = redlog::get_logger("p1ll.js.auto_cure");

  if (!session) {
    log.err("auto_cure called with no session");
    auto* report = new apply_report_wrapper();
    report->add_error("no session available");
    return report;
  }

  if (!is_defined(meta_obj)) {
    log.err("auto_cure called with invalid metadata object");
    auto* report = new apply_report_wrapper();
    report->add_error("invalid metadata object");
    return report;
  }

  auto recipe = parse_recipe(meta_obj);
  if (recipe.patches.empty()) {
    log.err("auto_cure called with empty patch list");
    auto* report = new apply_report_wrapper();
    report->add_error("recipe.patches is required");
    return report;
  }

  log.inf("executing auto_cure", redlog::field("name", recipe.name));
  auto plan = session->plan(recipe);
  if (!plan.ok()) {
    log.err("auto_cure planning failed", redlog::field("error", plan.status.message));
    auto* report = new apply_report_wrapper();
    report->add_error(plan.status.message.empty() ? "plan failed" : plan.status.message);
    return report;
  }

  auto applied = session->apply(plan.value);
  auto* report = new apply_report_wrapper(applied.value);
  if (!applied.ok()) {
    log.err("auto_cure apply failed", redlog::field("error", applied.status.message));
    if (!applied.status.message.empty()) {
      report->add_error(applied.status.message);
    }
  }
  log.inf(
      "auto_cure completed", redlog::field("success", report->success), redlog::field("applied", report->applied),
      redlog::field("failed", report->failed)
  );
  return report;
}

inline void setup_p1ll_js_bindings(jnjs::context& js_ctx, engine::session& session) {
  auto log = redlog::get_logger("p1ll.js_bindings");
  log.inf("setting up js bindings", redlog::field("mode", session.is_dynamic() ? "dynamic" : "static"));
  js_ctx.install_class<apply_report_wrapper>();
  js_ctx.install_class<scan_result_wrapper>();
  js_ctx.install_class<module_info_wrapper>();
  js_ctx.install_class<signature_wrapper>();
  js_ctx.install_class<patch_wrapper>();
  js_ctx.install_class<p1ll_api>();

  auto api = new p1ll_api(&session);
  js_ctx.set_global("p1", api);
  log.inf("js bindings registered");
}

} // namespace p1ll::scripting::js
