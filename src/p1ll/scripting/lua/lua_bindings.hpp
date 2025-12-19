#pragma once

// Header-only standalone p1ll lua bindings for w1script integration
// Converted from lua_bindings.cpp to be self-contained

#include <sol/sol.hpp>
#include <redlog.hpp>

// Core p1ll includes
#include "p1ll/core/types.hpp"
#include "p1ll/core/context.hpp"
#include "p1ll/core/signature.hpp"
#include "p1ll/engine/auto_cure.hpp"
#include "p1ll/engine/signature_scanner.hpp"
#include "p1ll/engine/memory_scanner.hpp"
#include "p1ll/utils/hex_utils.hpp"

// Standard library includes
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <optional>
#include <cctype>

namespace p1ll::scripting {

namespace bindings {

inline void setup_core_types(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.core");
  log.dbg("setting up core types");

  // expose cure_result for return values
  lua.new_usertype<cure_result>(
      "cure_result", "success", &cure_result::success, "patches_applied", &cure_result::patches_applied,
      "patches_failed", &cure_result::patches_failed, "error_messages", &cure_result::error_messages, "has_errors",
      &cure_result::has_errors
  );

  // expose search_result for manual api
  lua.new_usertype<search_result>(
      "search_result", "address", &search_result::address, "region_name", &search_result::region_name, "section_name",
      &search_result::section_name
  );

  // expose module_info for manual api
  lua.new_usertype<module_info>(
      "module_info", "name", &module_info::name, "path", &module_info::path, "base_address", &module_info::base_address,
      "size", &module_info::size, "permissions", &module_info::permissions, "is_system_module",
      &module_info::is_system_module
  );

  log.dbg("core types registered");
}

inline void setup_signature_api(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.signature");
  log.dbg("setting up signature api");

  // expose signature_decl
  lua.new_usertype<signature_decl>(
      "signature_decl", "pattern", &signature_decl::pattern, "to_string", &signature_decl::to_string
  );

  // p1.sig(pattern, opts) - create signature object with optional options table
  p1_module.set_function("sig", [](const std::string& pattern, sol::optional<sol::table> opts) -> signature_decl {
    // validate pattern
    if (pattern.empty()) {
      throw std::invalid_argument("sig: pattern cannot be empty");
    }

    // basic hex pattern validation - should contain only hex chars, spaces, and wildcards
    for (char c : pattern) {
      if (!std::isxdigit(c) && c != ' ' && c != '?' && c != '\t' && c != '\n' && c != '\r') {
        if (c < 32 || c > 126) { // non-printable
          throw std::invalid_argument("sig: pattern contains invalid character (non-printable)");
        }
      }
    }

    if (opts) {
      sol::table options = *opts;

      // check for filter option
      auto filter_opt = options["filter"];
      // check for single option
      auto single_opt = options["single"];

      signature_query_filter filter;
      bool single = false;

      if (filter_opt.valid()) {
        sol::object filter_obj = filter_opt;
        if (filter_obj.is<std::string>()) {
          filter.pattern = filter_obj.as<std::string>();
        } else {
          throw std::invalid_argument("sig: filter option must be a string");
        }
      }

      if (single_opt.valid()) {
        sol::object single_obj = single_opt;
        if (single_obj.is<bool>()) {
          single = single_obj.as<bool>();
        } else {
          throw std::invalid_argument("sig: single option must be a boolean");
        }
      }

      // if we have either filter or single, create with those options
      if (filter_opt.valid() || single_opt.valid()) {
        return signature_decl(pattern, filter, single);
      }
    }
    return signature_decl(pattern);
  });

  log.dbg("signature api registered");
}

inline void setup_patch_api(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.patch");
  log.dbg("setting up patch api");

  // p1.patch(sig_obj_or_string, offset, replace, opts) - create patch declaration
  p1_module.set_function(
      "patch",
      [](sol::object sig_param, uint64_t offset, const std::string& replace,
         sol::optional<sol::table> opts) -> patch_decl {
        patch_decl patch;

        // validate and convert signature parameter
        if (sig_param.is<signature_decl>()) {
          patch.signature = sig_param.as<signature_decl>();
        } else if (sig_param.is<std::string>()) {
          // auto-convert string to signature_decl with warning
          std::string sig_str = sig_param.as<std::string>();
          if (sig_str.empty()) {
            throw std::invalid_argument("patch: signature string cannot be empty");
          }

          // warn about direct string usage
          auto log = redlog::get_logger("p1ll.bindings.patch");
          log.warn(
              "patch: using raw string signature (recommend using p1.sig() instead)",
              redlog::field("signature", sig_str.length() > 50 ? sig_str.substr(0, 50) + "..." : sig_str)
          );

          patch.signature = signature_decl(sig_str);
        } else {
          throw std::invalid_argument("patch: first argument must be a signature object or string");
        }

        // validate replace pattern
        if (replace.empty()) {
          throw std::invalid_argument("patch: replace pattern cannot be empty");
        }

        // validate hex pattern for replace
        for (char c : replace) {
          if (!std::isxdigit(c) && c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            if (c < 32 || c > 126) { // non-printable
              throw std::invalid_argument("patch: replace pattern contains invalid character (non-printable)");
            }
          }
        }

        patch.offset = offset;
        patch.pattern = replace;
        patch.required = true; // default to required

        // parse options table if provided
        if (opts) {
          sol::table options = *opts;

          // required flag
          auto required = options["required"];
          if (required.valid() && required.is<bool>()) {
            patch.required = required;
          }
        }

        return patch;
      }
  );

  log.dbg("patch api registered");
}

inline void setup_auto_cure_api(sol::state& lua, sol::table& p1_module, const context& ctx) {
  auto log = redlog::get_logger("p1ll.bindings.auto_cure");
  log.dbg("setting up auto-cure api");

  // p1.auto_cure(meta) - execute auto-cure
  p1_module.set_function("auto_cure", [&ctx](sol::table meta_table) -> cure_result {
    auto log = redlog::get_logger("p1ll.lua.auto_cure");

    try {
      // parse metadata
      cure_metadata meta;
      auto name = meta_table["name"];
      if (name.valid() && name.is<std::string>()) {
        meta.name = name;
      }

      auto platforms = meta_table["platforms"];
      if (platforms.valid() && platforms.is<sol::table>()) {
        sol::table platforms_tbl = platforms;
        for (auto& pair : platforms_tbl) {
          sol::object value = pair.second;
          if (value.is<std::string>()) {
            std::string platform_str = value.as<std::string>();
            meta.platforms.push_back(platform_str);
          }
        }
      }

      // parse platform-specific signatures map
      platform_signature_map signatures;
      auto sigs_table = meta_table["sigs"];
      if (sigs_table.valid() && sigs_table.is<sol::table>()) {
        sol::table sigs_tbl = sigs_table;
        for (auto& pair : sigs_tbl) {
          sol::object platform_key = pair.first;
          sol::object sig_list = pair.second;
          if (platform_key.is<std::string>() && sig_list.is<sol::table>()) {
            std::vector<signature_decl> platform_sigs;
            sol::table sig_tbl = sig_list.as<sol::table>();

            for (auto& sig_pair : sig_tbl) {
              sol::object sig_obj = sig_pair.second;
              if (sig_obj.is<signature_decl>()) {
                signature_decl sig = sig_obj.as<signature_decl>();
                platform_sigs.push_back(sig);
              }
            }

            std::string platform_str = platform_key.as<std::string>();
            signatures[platform_str] = platform_sigs;
          }
        }
      }

      // parse platform-specific patches map
      platform_patch_map patches;
      auto patches_table = meta_table["patches"];
      if (patches_table.valid() && patches_table.is<sol::table>()) {
        sol::table patches_tbl = patches_table;
        for (auto& pair : patches_tbl) {
          sol::object platform_key = pair.first;
          sol::object patch_list = pair.second;
          if (platform_key.is<std::string>() && patch_list.is<sol::table>()) {
            std::vector<patch_decl> platform_patches;
            sol::table patch_tbl = patch_list.as<sol::table>();

            for (auto& patch_pair : patch_tbl) {
              sol::object patch_obj = patch_pair.second;
              if (patch_obj.is<patch_decl>()) {
                patch_decl patch = patch_obj.as<patch_decl>();
                platform_patches.push_back(patch);
              }
            }

            std::string platform_str = platform_key.as<std::string>();
            patches[platform_str] = platform_patches;
          }
        }
      }

      // use the context passed to bindings setup
      log.inf(
          "executing auto-cure from lua", redlog::field("name", meta.name),
          redlog::field("platforms", meta.platforms.size()), redlog::field("signatures", signatures.size()),
          redlog::field("patch_groups", patches.size())
      );

      // create auto_cure instance with context and execute
      engine::auto_cure cure(ctx);
      cure_config config{meta, signatures, patches};
      return cure.execute_dynamic(config);

    } catch (const std::exception& e) {
      log.err("auto-cure execution failed", redlog::field("error", e.what()));
      cure_result result;
      result.add_error("lua auto-cure failed: " + std::string(e.what()));
      return result;
    }
  });

  log.dbg("auto-cure api registered");
}

inline void setup_manual_api(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.manual");
  log.dbg("setting up manual api");

  // p1.get_modules(filter) - get modules matching filter
  p1_module.set_function("get_modules", [](sol::optional<sol::object> filter_opt) -> std::vector<module_info> {
    signature_query_filter filter;

    if (filter_opt) {
      if (filter_opt->is<std::string>()) {
        // simple string filter
        filter.pattern = filter_opt->as<std::string>();
      } else if (filter_opt->is<sol::table>()) {
        // table filter for backward compatibility
        sol::table filter_table = filter_opt->as<sol::table>();
        auto pattern = filter_table["pattern"];
        if (pattern.valid() && pattern.is<std::string>()) {
          filter.pattern = pattern;
        }
      }
    }

    engine::memory_scanner scanner;
    auto regions_opt = scanner.get_memory_regions(filter);
    std::vector<module_info> result;
    if (regions_opt) {
      for (const auto& region : *regions_opt) {
        if (!region.is_executable || region.name.empty()) {
          continue;
        }
        module_info mod;
        mod.name = region.name;
        mod.path = region.name;
        mod.base_address = region.base_address;
        mod.size = region.size;
        mod.permissions = std::string("r") +
                          (has_protection(region.protection, engine::memory_protection::write) ? "w" : "-") +
                          (has_protection(region.protection, engine::memory_protection::execute) ? "x" : "-");
        mod.is_system_module = region.is_system;
        result.push_back(mod);
      }
    }
    return result;
  });

  // p1.search_sig(pattern, opts) - search for signature with options
  p1_module.set_function(
      "search_sig", [&lua](const std::string& pattern, sol::optional<sol::object> opts_param) -> sol::object {
        auto log = redlog::get_logger("p1ll.lua.search_sig");

        signature_query_filter filter;
        bool single = false;

        // parse options - can be string (backward compat) or table
        if (opts_param) {
          if (opts_param->is<std::string>()) {
            // backward compatibility: treat string as filter
            filter.pattern = opts_param->as<std::string>();
          } else if (opts_param->is<sol::table>()) {
            // new style: options table
            sol::table opts = opts_param->as<sol::table>();

            // filter option
            auto filter_opt = opts["filter"];
            if (filter_opt.valid()) {
              sol::object filter_obj = filter_opt;
              if (filter_obj.is<std::string>()) {
                filter.pattern = filter_obj.as<std::string>();
              }
            }

            // single option
            auto single_opt = opts["single"];
            if (single_opt.valid()) {
              sol::object single_obj = single_opt;
              if (single_obj.is<bool>()) {
                single = single_obj.as<bool>();
              }
            }
          }
        }

        // perform the search
        // compile the signature pattern
        auto compiled_sig = compile_signature(pattern);
        if (!compiled_sig) {
          log.err("search_sig: failed to compile signature pattern", redlog::field("pattern", pattern));
          return sol::lua_nil;
        }

        engine::process_address_space space;
        engine::signature_scanner scanner(space);
        auto search_results_opt = scanner.scan(*compiled_sig, filter);
        if (!search_results_opt) {
          log.err("search_sig: search failed", redlog::field("pattern", pattern));
          return sol::lua_nil;
        }

        std::vector<search_result> results = *search_results_opt;

        // handle single mode
        if (single) {
          if (results.empty()) {
            log.err("search_sig: no matches found (expected exactly 1)", redlog::field("pattern", pattern));
            return sol::lua_nil;
          } else if (results.size() > 1) {
            log.err(
                "search_sig: multiple matches found (expected exactly 1)", redlog::field("pattern", pattern),
                redlog::field("count", results.size())
            );
            for (size_t i = 0; i < results.size(); ++i) {
              log.inf(redlog::fmt("  match %zu: address=0x%llx", i, results[i].address));
            }
            return sol::lua_nil;
          }
          // exactly one match - return the address directly
          return sol::make_object(lua, results[0].address);
        }

        // normal mode - return array of results
        return sol::make_object(lua, results);
      }
  );

  log.dbg("manual api registered");
}

inline void setup_utilities(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.utilities");
  log.dbg("setting up utilities");

  // === hex utilities ===
  p1_module.set_function("str2hex", [](const std::string& str) -> std::string { return p1ll::utils::str2hex(str); });

  p1_module.set_function("hex2str", [](const std::string& hex) -> std::string { return p1ll::utils::hex2str(hex); });

  p1_module.set_function("format_address", [](uint64_t address) -> std::string {
    return p1ll::utils::format_address(address);
  });

  // === logging functions ===
  p1_module.set_function("log_info", [](const std::string& msg) {
    auto log = redlog::get_logger("p1ll.lua");
    log.inf(msg);
  });

  p1_module.set_function("log_warn", [](const std::string& msg) {
    auto log = redlog::get_logger("p1ll.lua");
    log.wrn(msg);
  });

  p1_module.set_function("log_err", [](const std::string& msg) {
    auto log = redlog::get_logger("p1ll.lua");
    log.err(msg);
  });

  p1_module.set_function("log_dbg", [](const std::string& msg) {
    auto log = redlog::get_logger("p1ll.lua");
    log.dbg(msg);
  });

  log.dbg("utilities registered");
}

inline void setup_auto_cure_api_with_buffer(
    sol::state& lua, sol::table& p1_module, const context& ctx, std::vector<uint8_t>& buffer_data
) {
  auto log = redlog::get_logger("p1ll.bindings.auto_cure");
  log.dbg("setting up auto-cure api with buffer");

  p1_module.set_function("auto_cure", [&ctx, &buffer_data](sol::table meta_table) -> cure_result {
    auto log = redlog::get_logger("p1ll.lua.auto_cure");

    try {
      cure_metadata meta;
      auto name = meta_table["name"];
      if (name.valid() && name.is<std::string>()) {
        meta.name = name;
      }

      auto platforms = meta_table["platforms"];
      if (platforms.valid() && platforms.is<sol::table>()) {
        sol::table platforms_tbl = platforms;
        for (auto& pair : platforms_tbl) {
          sol::object value = pair.second;
          if (value.is<std::string>()) {
            std::string platform_str = value.as<std::string>();
            meta.platforms.push_back(platform_str);
          }
        }
      }

      platform_signature_map signatures;
      auto sigs_table = meta_table["sigs"];
      if (sigs_table.valid() && sigs_table.is<sol::table>()) {
        sol::table sigs_tbl = sigs_table;
        for (auto& pair : sigs_tbl) {
          sol::object platform_key = pair.first;
          sol::object sig_list = pair.second;
          if (platform_key.is<std::string>() && sig_list.is<sol::table>()) {
            std::vector<signature_decl> platform_sigs;
            sol::table sig_tbl = sig_list.as<sol::table>();

            for (auto& sig_pair : sig_tbl) {
              sol::object sig_obj = sig_pair.second;
              if (sig_obj.is<signature_decl>()) {
                signature_decl sig = sig_obj.as<signature_decl>();
                platform_sigs.push_back(sig);
              }
            }

            std::string platform_str = platform_key.as<std::string>();
            signatures[platform_str] = platform_sigs;
          }
        }
      }

      platform_patch_map patches;
      auto patches_table = meta_table["patches"];
      if (patches_table.valid() && patches_table.is<sol::table>()) {
        sol::table patches_tbl = patches_table;
        for (auto& pair : patches_tbl) {
          sol::object platform_key = pair.first;
          sol::object patch_list = pair.second;
          if (platform_key.is<std::string>() && patch_list.is<sol::table>()) {
            std::vector<patch_decl> platform_patches;
            sol::table patch_tbl = patch_list.as<sol::table>();

            for (auto& patch_pair : patch_tbl) {
              sol::object patch_obj = patch_pair.second;
              if (patch_obj.is<patch_decl>()) {
                patch_decl patch = patch_obj.as<patch_decl>();
                platform_patches.push_back(patch);
              }
            }

            std::string platform_str = platform_key.as<std::string>();
            patches[platform_str] = platform_patches;
          }
        }
      }

      log.inf("executing auto-cure", redlog::field("name", meta.name));

      engine::auto_cure cure(ctx);
      cure_config config{meta, signatures, patches};
      return cure.execute_static(buffer_data, config);

    } catch (const std::exception& e) {
      log.err("auto-cure failed", redlog::field("error", e.what()));
      cure_result result;
      result.add_error(std::string("auto-cure exception: ") + e.what());
      return result;
    }
  });

  log.dbg("auto-cure api registered");
}

} // namespace bindings

inline void setup_p1ll_bindings(sol::state& lua, const context& ctx) {
  auto log = redlog::get_logger("p1ll.bindings");
  log.inf("setting up modular p1ll bindings");

  // create the main p1 module (short and beautiful)
  sol::table p1_module = lua.create_table();

  // setup all binding modules in logical order
  log.dbg("setting up core types");
  bindings::setup_core_types(lua, p1_module);

  log.dbg("setting up signature api");
  bindings::setup_signature_api(lua, p1_module);

  log.dbg("setting up patch api");
  bindings::setup_patch_api(lua, p1_module);

  log.dbg("setting up auto-cure api");
  bindings::setup_auto_cure_api(lua, p1_module, ctx);

  log.dbg("setting up manual api");
  bindings::setup_manual_api(lua, p1_module);

  log.dbg("setting up utilities");
  bindings::setup_utilities(lua, p1_module);

  // register the p1 module with the lua state
  lua["p1"] = p1_module;

  log.inf("all p1ll bindings registered successfully");
  log.dbg("available in lua as: p1.sig(), p1.patch(), p1.auto_cure(), p1.str2hex(), etc.");
}

inline void setup_p1ll_bindings_with_buffer(sol::state& lua, const context& ctx, std::vector<uint8_t>& buffer_data) {
  auto log = redlog::get_logger("p1ll.bindings");
  log.inf("setting up p1ll bindings with buffer");

  sol::table p1_module = lua.create_table();

  bindings::setup_core_types(lua, p1_module);
  bindings::setup_signature_api(lua, p1_module);
  bindings::setup_patch_api(lua, p1_module);
  bindings::setup_auto_cure_api_with_buffer(lua, p1_module, ctx, buffer_data);
  bindings::setup_manual_api(lua, p1_module);
  bindings::setup_utilities(lua, p1_module);

  lua["p1"] = p1_module;
  log.inf("p1ll bindings registered");
}

} // namespace p1ll::scripting
