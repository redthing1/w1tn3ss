/**
 * @file p1ll_c.cpp
 * @brief C API implementation wrapping the p1ll engine session
 */

#include "p1ll_c.h"
#include "../p1ll.hpp"
#include "../engine/platform/platform.hpp"
#include "../engine/pattern.hpp"
#include "../utils/hex_utils.hpp"

#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

thread_local std::string last_error;

static void set_error(const std::string& msg) { last_error = msg; }
static void clear_error() { last_error.clear(); }

struct p1ll_session {
  std::unique_ptr<p1ll::engine::session> session;
};

static p1ll::engine::scan_options convert_scan_options(const p1ll_scan_options_t* options) {
  p1ll::engine::scan_options out;
  if (!options) {
    return out;
  }
  if (options->filter.name_regex) {
    out.filter.name_regex = options->filter.name_regex;
  }
  out.filter.only_executable = options->filter.only_executable != 0;
  out.filter.exclude_system = options->filter.exclude_system != 0;
  out.filter.min_size = options->filter.min_size;
  if (options->filter.has_min_address) {
    out.filter.min_address = options->filter.min_address;
  }
  if (options->filter.has_max_address) {
    out.filter.max_address = options->filter.max_address;
  }
  out.single = options->single != 0;
  out.max_matches = options->max_matches;
  return out;
}

static std::vector<std::string> convert_platforms(const char** platforms, size_t count) {
  std::vector<std::string> result;
  if (!platforms) {
    return result;
  }
  for (size_t i = 0; i < count; ++i) {
    if (platforms[i]) {
      result.push_back(platforms[i]);
    }
  }
  return result;
}

static p1ll::engine::signature_spec convert_signature_spec(const p1ll_signature_spec_t& spec) {
  p1ll::engine::signature_spec out;
  if (spec.pattern) {
    out.pattern = spec.pattern;
  }
  out.options = convert_scan_options(&spec.options);
  out.platforms = convert_platforms(spec.platforms, spec.platform_count);
  out.required = spec.required != 0;
  return out;
}

static p1ll::engine::patch_spec convert_patch_spec(const p1ll_patch_spec_t& spec) {
  p1ll::engine::patch_spec out;
  out.signature = convert_signature_spec(spec.signature);
  out.offset = spec.offset;
  if (spec.patch) {
    out.patch = spec.patch;
  }
  out.platforms = convert_platforms(spec.platforms, spec.platform_count);
  out.required = spec.required != 0;
  return out;
}

p1ll_session_t p1ll_session_create_process(void) {
  try {
    clear_error();
    auto session = std::make_unique<p1ll::engine::session>(p1ll::engine::session::for_process());
    return new p1ll_session{std::move(session)};
  } catch (const std::exception& e) {
    set_error("failed to create process session: " + std::string(e.what()));
    return nullptr;
  }
}

p1ll_session_t p1ll_session_create_buffer(uint8_t* buffer, size_t size) {
  if (!buffer || size == 0) {
    set_error("invalid buffer");
    return nullptr;
  }
  try {
    clear_error();
    auto session =
        std::make_unique<p1ll::engine::session>(p1ll::engine::session::for_buffer(std::span<uint8_t>(buffer, size)));
    return new p1ll_session{std::move(session)};
  } catch (const std::exception& e) {
    set_error("failed to create buffer session: " + std::string(e.what()));
    return nullptr;
  }
}

p1ll_session_t p1ll_session_create_buffer_with_platform(uint8_t* buffer, size_t size, const char* platform_key) {
  if (!buffer || size == 0) {
    set_error("invalid buffer");
    return nullptr;
  }
  if (!platform_key) {
    set_error("invalid platform key");
    return nullptr;
  }
  try {
    clear_error();
    auto parsed = p1ll::engine::platform::parse_platform(platform_key);
    if (!parsed.ok()) {
      set_error(parsed.status_info.message.empty() ? "invalid platform key" : parsed.status_info.message);
      return nullptr;
    }
    auto session = std::make_unique<p1ll::engine::session>(
        p1ll::engine::session::for_buffer(std::span<uint8_t>(buffer, size), parsed.value)
    );
    return new p1ll_session{std::move(session)};
  } catch (const std::exception& e) {
    set_error("failed to create buffer session: " + std::string(e.what()));
    return nullptr;
  }
}

void p1ll_session_destroy(p1ll_session_t session) {
  if (session) {
    delete session;
  }
}

int p1ll_scan(
    p1ll_session_t session, const char* pattern, const p1ll_scan_options_t* options, p1ll_scan_result_t** out_results,
    size_t* out_count
) {
  if (!session || !pattern || !out_results || !out_count) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    auto scan_opts = convert_scan_options(options);
    auto result = session->session->scan(pattern, scan_opts);
    if (!result.ok()) {
      set_error(result.status_info.message.empty() ? "scan failed" : result.status_info.message);
      return P1LL_ERROR;
    }

    *out_count = result.value.size();
    if (*out_count == 0) {
      *out_results = nullptr;
      return P1LL_SUCCESS;
    }

    *out_results = static_cast<p1ll_scan_result_t*>(calloc(*out_count, sizeof(p1ll_scan_result_t)));
    if (!*out_results) {
      set_error("failed to allocate scan results");
      return P1LL_ERROR;
    }

    for (size_t i = 0; i < *out_count; ++i) {
      (*out_results)[i].address = result.value[i].address;
      strncpy(
          (*out_results)[i].region_name, result.value[i].region_name.c_str(), sizeof((*out_results)[i].region_name) - 1
      );
      (*out_results)[i].region_name[sizeof((*out_results)[i].region_name) - 1] = '\0';
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in scan: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

void p1ll_free_scan_results(p1ll_scan_result_t* results) { free(results); }

int p1ll_plan(p1ll_session_t session, const p1ll_recipe_t* recipe, p1ll_plan_entry_t** out_entries, size_t* out_count) {
  if (!session || !recipe || !out_entries || !out_count) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    p1ll::engine::recipe plan_recipe;
    if (recipe->name) {
      plan_recipe.name = recipe->name;
    }
    plan_recipe.platforms = convert_platforms(recipe->platforms, recipe->platform_count);

    for (size_t i = 0; i < recipe->validation_count; ++i) {
      plan_recipe.validations.push_back(convert_signature_spec(recipe->validations[i]));
    }
    for (size_t i = 0; i < recipe->patch_count; ++i) {
      plan_recipe.patches.push_back(convert_patch_spec(recipe->patches[i]));
    }

    auto plan = session->session->plan(plan_recipe);
    if (!plan.ok()) {
      set_error(plan.status_info.message.empty() ? "plan failed" : plan.status_info.message);
      return P1LL_ERROR;
    }

    *out_count = plan.value.size();
    if (*out_count == 0) {
      *out_entries = nullptr;
      return P1LL_SUCCESS;
    }

    *out_entries = static_cast<p1ll_plan_entry_t*>(calloc(*out_count, sizeof(p1ll_plan_entry_t)));
    if (!*out_entries) {
      set_error("failed to allocate plan entries");
      return P1LL_ERROR;
    }

    for (size_t i = 0; i < *out_count; ++i) {
      const auto& entry = plan.value[i];
      auto& out = (*out_entries)[i];
      out.address = entry.address;
      out.size = entry.patch_bytes.size();
      out.required = entry.spec.required ? 1 : 0;

      out.patch_bytes = static_cast<uint8_t*>(malloc(out.size));
      out.patch_mask = static_cast<uint8_t*>(malloc(out.size));
      if (!out.patch_bytes || !out.patch_mask) {
        p1ll_free_plan_entries(*out_entries, i + 1);
        *out_entries = nullptr;
        *out_count = 0;
        set_error("failed to allocate patch bytes");
        return P1LL_ERROR;
      }

      std::memcpy(out.patch_bytes, entry.patch_bytes.data(), out.size);
      std::memcpy(out.patch_mask, entry.patch_mask.data(), out.size);
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in plan: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

void p1ll_free_plan_entries(p1ll_plan_entry_t* entries, size_t count) {
  if (!entries) {
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    free(entries[i].patch_bytes);
    free(entries[i].patch_mask);
  }
  free(entries);
}

int p1ll_apply(
    p1ll_session_t session, const p1ll_plan_entry_t* entries, size_t count, p1ll_apply_report_t* out_report
) {
  if (!session || !entries || !out_report) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    std::vector<p1ll::engine::plan_entry> plan_entries;
    plan_entries.reserve(count);
    for (size_t i = 0; i < count; ++i) {
      p1ll::engine::plan_entry entry;
      entry.address = entries[i].address;
      entry.patch_bytes.assign(entries[i].patch_bytes, entries[i].patch_bytes + entries[i].size);
      entry.patch_mask.assign(entries[i].patch_mask, entries[i].patch_mask + entries[i].size);
      entry.spec.required = entries[i].required != 0;
      plan_entries.push_back(std::move(entry));
    }

    auto applied = session->session->apply(plan_entries);
    out_report->success = applied.value.success ? 1 : 0;
    out_report->applied = applied.value.applied;
    out_report->failed = applied.value.failed;

    if (!applied.ok()) {
      set_error(applied.status_info.message.empty() ? "apply failed" : applied.status_info.message);
      return P1LL_ERROR;
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in apply: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

int p1ll_validate_pattern(const char* hex_pattern) {
  if (!hex_pattern) {
    return 0;
  }
  auto parsed = p1ll::engine::parse_signature(hex_pattern);
  return parsed.ok() ? 1 : 0;
}

int p1ll_hex_string_to_bytes(const char* hex, uint8_t** out_bytes, size_t* out_size) {
  if (!hex || !out_bytes || !out_size) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    std::string hex_str = hex;
    std::string clean_hex;
    for (char c : hex_str) {
      if (c != ' ') {
        if (!p1ll::utils::is_hex_digit(c)) {
          set_error("invalid hex character");
          return P1LL_ERROR;
        }
        clean_hex += c;
      }
    }

    if (clean_hex.length() % 2 != 0) {
      set_error("hex string must have even length");
      return P1LL_ERROR;
    }

    *out_size = clean_hex.length() / 2;
    *out_bytes = static_cast<uint8_t*>(malloc(*out_size));
    if (!*out_bytes) {
      set_error("failed to allocate bytes array");
      return P1LL_ERROR;
    }

    for (size_t i = 0; i < *out_size; ++i) {
      uint8_t high = p1ll::utils::parse_hex_digit(clean_hex[i * 2]);
      uint8_t low = p1ll::utils::parse_hex_digit(clean_hex[i * 2 + 1]);
      (*out_bytes)[i] = (high << 4) | low;
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in hex_string_to_bytes: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

char* p1ll_bytes_to_hex_string(const uint8_t* bytes, size_t size) {
  if (!bytes) {
    set_error("invalid parameters");
    return nullptr;
  }

  try {
    clear_error();
    std::vector<uint8_t> byte_vec(bytes, bytes + size);
    std::string hex_str = p1ll::utils::format_bytes(byte_vec);

    char* result = static_cast<char*>(malloc(hex_str.length() + 1));
    if (!result) {
      set_error("failed to allocate string");
      return nullptr;
    }

    std::strcpy(result, hex_str.c_str());
    return result;
  } catch (const std::exception& e) {
    set_error("exception in bytes_to_hex_string: " + std::string(e.what()));
    return nullptr;
  }
}

char* p1ll_format_address(uint64_t address) {
  try {
    clear_error();
    std::string addr_str = p1ll::utils::format_address(address);

    char* result = static_cast<char*>(malloc(addr_str.length() + 1));
    if (!result) {
      set_error("failed to allocate string");
      return nullptr;
    }

    std::strcpy(result, addr_str.c_str());
    return result;
  } catch (const std::exception& e) {
    set_error("exception in format_address: " + std::string(e.what()));
    return nullptr;
  }
}

void p1ll_free_bytes(uint8_t* bytes) { free(bytes); }
void p1ll_free_string(char* str) { free(str); }

int p1ll_has_scripting_support(void) { return p1ll::has_scripting_support() ? 1 : 0; }

const char* p1ll_get_last_error(void) { return last_error.c_str(); }
