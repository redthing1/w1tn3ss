#pragma once

#include <sol/sol.hpp>
#include <redlog.hpp>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <limits>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

#include "p1ll/engine/result.hpp"
#include "p1ll/engine/session.hpp"
#include "p1ll/engine/types.hpp"
#include "p1ll/utils/hex_utils.hpp"

namespace p1ll::scripting::lua {

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

struct apply_report_wrapper {
  bool success = false;
  int applied = 0;
  int failed = 0;
  std::vector<std::string> error_messages;
  std::vector<std::string> diagnostics;

  apply_report_wrapper() = default;
  explicit apply_report_wrapper(const engine::apply_report& report)
      : success(report.success), applied(static_cast<int>(report.applied)), failed(static_cast<int>(report.failed)) {
    for (const auto& diag : report.diagnostics) {
      diagnostics.push_back(format_status(diag));
      if (!diag.message.empty()) {
        error_messages.push_back(diag.message);
      }
    }
  }

  void add_error(const std::string& message) {
    error_messages.push_back(message);
    diagnostics.push_back(format_status(engine::make_status(engine::error_code::invalid_argument, message)));
    success = false;
  }
};

struct scan_result_wrapper {
  uint64_t address = 0;
  std::string region_name;
};

struct module_info_wrapper {
  std::string name;
  std::string path;
  uint64_t base_address = 0;
  uint64_t size = 0;
  std::string permissions;
  bool is_system_module = false;
};

struct signature_wrapper {
  engine::signature_spec spec;
};

struct patch_wrapper {
  engine::patch_spec spec;
};

inline void apply_scan_options(engine::scan_options& options, const sol::table& opts) {
  sol::optional<std::string> filter = opts["filter"];
  if (filter) {
    options.filter.name_regex = *filter;
  }

  sol::optional<bool> single = opts["single"];
  if (single) {
    options.single = *single;
  }

  sol::optional<int> max_matches = opts["max_matches"];
  if (max_matches) {
    options.max_matches = static_cast<size_t>(*max_matches);
  }

  sol::optional<bool> only_exec = opts["only_executable"];
  if (only_exec) {
    options.filter.only_executable = *only_exec;
  }

  sol::optional<bool> exclude_system = opts["exclude_system"];
  if (exclude_system) {
    options.filter.exclude_system = *exclude_system;
  }

  sol::optional<int> min_size = opts["min_size"];
  if (min_size) {
    options.filter.min_size = static_cast<size_t>(*min_size);
  }

  sol::optional<uint64_t> min_addr = opts["min_address"];
  if (min_addr) {
    options.filter.min_address = *min_addr;
  }

  sol::optional<uint64_t> max_addr = opts["max_address"];
  if (max_addr) {
    options.filter.max_address = *max_addr;
  }
}

inline std::vector<std::string> parse_platform_list(const sol::object& value) {
  if (value.is<sol::table>()) {
    std::vector<std::string> platforms;
    sol::table table = value.as<sol::table>();
    for (const auto& entry : table) {
      if (entry.second.is<std::string>()) {
        platforms.push_back(entry.second.as<std::string>());
      }
    }
    return platforms;
  }
  return {};
}

inline engine::recipe parse_recipe(const sol::table& meta) {
  engine::recipe recipe;

  sol::optional<std::string> name_val = meta["name"];
  if (name_val) {
    recipe.name = *name_val;
  }

  sol::object platforms_val = meta["platforms"];
  if (platforms_val.valid()) {
    recipe.platforms = parse_platform_list(platforms_val);
  }

  sol::optional<sol::table> validations_val = meta["validations"];
  if (validations_val) {
    sol::table list = *validations_val;
    for (const auto& entry : list) {
      if (entry.second.is<signature_wrapper>()) {
        recipe.validations.push_back(entry.second.as<signature_wrapper>().spec);
      }
    }
  }

  sol::optional<sol::table> sigs_val = meta["sigs"];
  if (sigs_val) {
    sol::table map = *sigs_val;
    for (const auto& entry : map) {
      std::string platform_key = entry.first.as<std::string>();
      sol::table sig_list = entry.second.as<sol::table>();
      for (const auto& sig_entry : sig_list) {
        if (!sig_entry.second.is<signature_wrapper>()) {
          continue;
        }
        engine::signature_spec spec = sig_entry.second.as<signature_wrapper>().spec;
        spec.platforms.clear();
        if (platform_key != "*" && platform_key != "*:*") {
          spec.platforms.push_back(platform_key);
        }
        recipe.validations.push_back(spec);
      }
    }
  }

  sol::optional<sol::table> patches_val = meta["patches"];
  if (patches_val) {
    sol::table patch_table = *patches_val;
    if (patch_table.size() > 0 && patch_table[1].valid()) {
      for (const auto& entry : patch_table) {
        if (entry.second.is<patch_wrapper>()) {
          recipe.patches.push_back(entry.second.as<patch_wrapper>().spec);
        }
      }
    } else {
      for (const auto& entry : patch_table) {
        std::string platform_key = entry.first.as<std::string>();
        sol::table patch_list = entry.second.as<sol::table>();
        for (const auto& patch_entry : patch_list) {
          if (!patch_entry.second.is<patch_wrapper>()) {
            continue;
          }
          engine::patch_spec spec = patch_entry.second.as<patch_wrapper>().spec;
          spec.platforms.clear();
          if (platform_key != "*" && platform_key != "*:*") {
            spec.platforms.push_back(platform_key);
          }
          recipe.patches.push_back(spec);
        }
      }
    }
  }

  return recipe;
}

inline void setup_p1ll_bindings(sol::state& lua, engine::session& session) {
  auto log = redlog::get_logger("p1ll.lua_bindings");
  log.inf("setting up lua bindings", redlog::field("mode", session.is_dynamic() ? "dynamic" : "static"));
  lua.new_usertype<apply_report_wrapper>(
      "apply_report",
      "success",
      &apply_report_wrapper::success,
      "applied",
      &apply_report_wrapper::applied,
      "failed",
      &apply_report_wrapper::failed,
      "error_messages",
      &apply_report_wrapper::error_messages,
      "diagnostics",
      &apply_report_wrapper::diagnostics
  );

  lua.new_usertype<scan_result_wrapper>(
      "scan_result", "address", &scan_result_wrapper::address, "region_name", &scan_result_wrapper::region_name
  );

  lua.new_usertype<module_info_wrapper>(
      "module_info",
      "name",
      &module_info_wrapper::name,
      "path",
      &module_info_wrapper::path,
      "base_address",
      &module_info_wrapper::base_address,
      "size",
      &module_info_wrapper::size,
      "permissions",
      &module_info_wrapper::permissions,
      "is_system_module",
      &module_info_wrapper::is_system_module
  );

  lua.new_usertype<signature_wrapper>("signature", "pattern", sol::property([](const signature_wrapper& sig) {
    return sig.spec.pattern;
  }));

  lua.new_usertype<patch_wrapper>("patch");

  sol::table p1_module = lua.create_named_table("p1");

  p1_module.set_function("str2hex", [](const std::string& str) { return p1ll::utils::str2hex(str); });
  p1_module.set_function("hex2str", [](const std::string& hex) { return p1ll::utils::hex2str(hex); });
  p1_module.set_function("format_address", [](uint64_t address) { return p1ll::utils::format_address(address); });

  p1_module.set_function("sig", [](const std::string& pattern, sol::optional<sol::table> opts) {
    engine::signature_spec spec;
    spec.pattern = pattern;
    if (opts) {
      apply_scan_options(spec.options, *opts);
      sol::optional<bool> required = (*opts)["required"];
      if (required) {
        spec.required = *required;
      }
      sol::object platforms = (*opts)["platforms"];
      if (platforms.valid()) {
        spec.platforms = parse_platform_list(platforms);
      }
    }
    signature_wrapper wrapper;
    wrapper.spec = std::move(spec);
    return wrapper;
  });

  p1_module.set_function(
      "patch",
      [](sol::object sig_param, int64_t offset, const std::string& pattern, sol::optional<sol::table> opts) {
        engine::patch_spec spec;
        if (sig_param.is<signature_wrapper>()) {
          spec.signature = sig_param.as<signature_wrapper>().spec;
        } else if (sig_param.is<std::string>()) {
          spec.signature.pattern = sig_param.as<std::string>();
        }
        spec.offset = offset;
        spec.patch = pattern;
        spec.required = true;

        if (opts) {
          sol::optional<bool> required = (*opts)["required"];
          if (required) {
            spec.required = *required;
          }
          sol::object platforms = (*opts)["platforms"];
          if (platforms.valid()) {
            spec.platforms = parse_platform_list(platforms);
          }
        }

        patch_wrapper wrapper;
        wrapper.spec = std::move(spec);
        return wrapper;
      }
  );

  p1_module.set_function("auto_cure", [&session](sol::table meta) {
    auto log = redlog::get_logger("p1ll.lua.auto_cure");
    auto recipe = parse_recipe(meta);
    apply_report_wrapper report;
    if (recipe.patches.empty()) {
      log.err("auto_cure called with empty patch list");
      report.add_error("recipe.patches is required");
      return report;
    }

    log.inf("executing auto_cure", redlog::field("name", recipe.name));
    auto plan = session.plan(recipe);
    if (!plan.ok()) {
      log.err("auto_cure planning failed", redlog::field("error", plan.status.message));
      report.add_error(plan.status.message.empty() ? "plan failed" : plan.status.message);
      return report;
    }

    auto applied = session.apply(plan.value);
    report = apply_report_wrapper(applied.value);
    if (!applied.ok()) {
      if (!applied.status.message.empty()) {
        report.add_error(applied.status.message);
      }
      log.err("auto_cure apply failed", redlog::field("error", applied.status.message));
    }
    log.inf(
        "auto_cure completed", redlog::field("success", report.success), redlog::field("applied", report.applied),
        redlog::field("failed", report.failed)
    );
    return report;
  });

  p1_module.set_function("get_modules", [&session](sol::optional<std::string> filter_pattern) {
    std::vector<module_info_wrapper> result;
    auto log = redlog::get_logger("p1ll.lua");
    if (!session.is_dynamic()) {
      log.dbg("get_modules unavailable in static mode");
      return result;
    }

    auto regions = session.regions(engine::scan_filter{});
    if (!regions.ok()) {
      log.err("get_modules failed", redlog::field("error", regions.status.message));
      return result;
    }

    std::optional<std::regex> filter_regex;
    if (filter_pattern && !filter_pattern->empty()) {
      try {
        filter_regex.emplace(*filter_pattern);
      } catch (const std::regex_error&) {
        log.err("invalid module filter regex");
        return result;
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

      module_info_wrapper mod;
      mod.name = name;
      mod.path = entry.path;
      mod.base_address = entry.base_address;
      mod.size = entry.end_address - entry.base_address;
      mod.permissions = std::string(engine::has_protection(entry.protection, engine::memory_protection::read) ? "r" : "-") +
                        (engine::has_protection(entry.protection, engine::memory_protection::write) ? "w" : "-") +
                        (engine::has_protection(entry.protection, engine::memory_protection::execute) ? "x" : "-");
      mod.is_system_module = entry.is_system;
      result.push_back(mod);
    }

    std::sort(result.begin(), result.end(), [](const module_info_wrapper& a, const module_info_wrapper& b) {
      return a.base_address < b.base_address;
    });

    log.dbg("found modules", redlog::field("count", result.size()));
    return result;
  });

  p1_module.set_function(
      "search_sig",
      [&session, &lua](const std::string& pattern, sol::optional<sol::table> opts) -> sol::object {
        auto log = redlog::get_logger("p1ll.lua");
        engine::scan_options options;
        if (opts) {
          apply_scan_options(options, *opts);
        }
        auto results = session.scan(pattern, options);
        if (!results.ok() || results.value.empty()) {
          if (!results.ok()) {
            log.err(
                "search failed", redlog::field("pattern", pattern),
                redlog::field("error", results.status.message)
            );
          } else {
            log.dbg("search returned no matches", redlog::field("pattern", pattern));
          }
          return sol::make_object(lua, sol::lua_nil);
        }
        if (options.single && results.value.size() != 1) {
          log.dbg(
              "single match required but search returned unexpected count",
              redlog::field("count", results.value.size())
          );
          return sol::make_object(lua, sol::lua_nil);
        }
        if (results.value.size() > 1) {
          log.wrn("multiple matches, returning first", redlog::field("count", results.value.size()));
        }
        scan_result_wrapper wrapper;
        wrapper.address = results.value.front().address;
        wrapper.region_name = results.value.front().region_name;
        return sol::make_object(lua, wrapper);
      }
  );

  p1_module.set_function(
      "search_sig_multiple",
      [&session](const std::string& pattern, sol::optional<sol::table> opts) -> std::vector<scan_result_wrapper> {
        std::vector<scan_result_wrapper> output;
        auto log = redlog::get_logger("p1ll.lua");
        engine::scan_options options;
        if (opts) {
          apply_scan_options(options, *opts);
        }
        auto results = session.scan(pattern, options);
        if (!results.ok()) {
          log.err(
              "search failed", redlog::field("pattern", pattern),
              redlog::field("error", results.status.message)
          );
          return output;
        }
        for (const auto& result : results.value) {
          scan_result_wrapper wrapper;
          wrapper.address = result.address;
          wrapper.region_name = result.region_name;
          output.push_back(wrapper);
        }
        log.dbg("search completed", redlog::field("results", output.size()));
        return output;
      }
  );
  log.inf("lua bindings registered");
}

} // namespace p1ll::scripting::lua
