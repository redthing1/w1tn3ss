#include "lua_bindings.hpp"
#include "../p1ll.hpp"
#include <redlog.hpp>

namespace p1ll::scripting {

void setup_p1ll_bindings(sol::state& lua) {
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
  bindings::setup_auto_cure_api(lua, p1_module);

  log.dbg("setting up manual api");
  bindings::setup_manual_api(lua, p1_module);

  log.dbg("setting up utilities");
  bindings::setup_utilities(lua, p1_module);

  // register the p1 module with the lua state
  lua["p1"] = p1_module;

  log.inf("all p1ll bindings registered successfully");
  log.dbg("available in lua as: p1.sig(), p1.patch(), p1.auto_cure(), p1.str2hex(), etc.");
}

namespace bindings {

void setup_core_types(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.core");
  log.dbg("setting up core types");

  // expose cure_result for return values
  lua.new_usertype<core::cure_result>(
      "cure_result", "success", &core::cure_result::success, "patches_applied", &core::cure_result::patches_applied,
      "patches_failed", &core::cure_result::patches_failed, "error_messages", &core::cure_result::error_messages,
      "has_errors", &core::cure_result::has_errors
  );

  // expose search_result for manual api
  lua.new_usertype<core::search_result>(
      "search_result", "address", &core::search_result::address, "region_name", &core::search_result::region_name,
      "section_name", &core::search_result::section_name
  );

  // expose module_info for manual api
  lua.new_usertype<core::module_info>(
      "module_info", "name", &core::module_info::name, "path", &core::module_info::path, "base_address",
      &core::module_info::base_address, "size", &core::module_info::size, "permissions",
      &core::module_info::permissions, "is_system_module", &core::module_info::is_system_module
  );

  log.dbg("core types registered");
}

void setup_signature_api(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.signature");
  log.dbg("setting up signature api");

  // expose signature_object
  lua.new_usertype<core::signature_object>(
      "signature_object", "pattern", &core::signature_object::pattern, "to_string", &core::signature_object::to_string
  );

  // p1.sig(pattern, opts) - create signature object with optional options table
  p1_module.set_function(
      "sig", [](const std::string& pattern, sol::optional<sol::table> opts) -> core::signature_object {
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
          if (filter_opt.valid()) {
            sol::object filter_obj = filter_opt;
            if (filter_obj.is<std::string>()) {
              core::signature_query_filter filter;
              filter.pattern = filter_obj.as<std::string>();
              return core::signature_object(pattern, filter);
            } else {
              throw std::invalid_argument("sig: filter option must be a string");
            }
          }
        }
        return core::signature_object(pattern);
      }
  );

  log.dbg("signature api registered");
}

void setup_patch_api(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.patch");
  log.dbg("setting up patch api");

  // p1.patch(sig_obj_or_string, offset, replace, opts) - create patch declaration
  p1_module.set_function(
      "patch",
      [](sol::object sig_param, uint64_t offset, const std::string& replace,
         sol::optional<sol::table> opts) -> core::patch_declaration {
        core::patch_declaration patch;

        // validate and convert signature parameter
        if (sig_param.is<core::signature_object>()) {
          patch.signature = sig_param.as<core::signature_object>();
        } else if (sig_param.is<std::string>()) {
          // auto-convert string to signature_object with warning
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

          patch.signature = core::signature_object(sig_str);
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

void setup_auto_cure_api(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.auto_cure");
  log.dbg("setting up auto-cure api");

  // p1.auto_cure(meta) - execute auto-cure
  p1_module.set_function("auto_cure", [&lua](sol::table meta_table) -> core::cure_result {
    auto log = redlog::get_logger("p1ll.lua.auto_cure");

    try {
      // parse metadata
      core::cure_metadata meta;
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
      core::platform_signature_map signatures;
      auto sigs_table = meta_table["sigs"];
      if (sigs_table.valid() && sigs_table.is<sol::table>()) {
        sol::table sigs_tbl = sigs_table;
        for (auto& pair : sigs_tbl) {
          sol::object platform_key = pair.first;
          sol::object sig_list = pair.second;
          if (platform_key.is<std::string>() && sig_list.is<sol::table>()) {
            std::vector<core::signature_object> platform_sigs;
            sol::table sig_tbl = sig_list.as<sol::table>();

            for (auto& sig_pair : sig_tbl) {
              sol::object sig_obj = sig_pair.second;
              if (sig_obj.is<core::signature_object>()) {
                core::signature_object sig = sig_obj.as<core::signature_object>();
                platform_sigs.push_back(sig);
              }
            }

            std::string platform_str = platform_key.as<std::string>();
            signatures[platform_str] = platform_sigs;
          }
        }
      }

      // parse platform-specific patches map
      core::platform_patch_map patches;
      auto patches_table = meta_table["patches"];
      if (patches_table.valid() && patches_table.is<sol::table>()) {
        sol::table patches_tbl = patches_table;
        for (auto& pair : patches_tbl) {
          sol::object platform_key = pair.first;
          sol::object patch_list = pair.second;
          if (platform_key.is<std::string>() && patch_list.is<sol::table>()) {
            std::vector<core::patch_declaration> platform_patches;
            sol::table patch_tbl = patch_list.as<sol::table>();

            for (auto& patch_pair : patch_tbl) {
              sol::object patch_obj = patch_pair.second;
              if (patch_obj.is<core::patch_declaration>()) {
                core::patch_declaration patch = patch_obj.as<core::patch_declaration>();
                platform_patches.push_back(patch);
              }
            }

            std::string platform_str = platform_key.as<std::string>();
            patches[platform_str] = platform_patches;
          }
        }
      }

      // get current context to determine mode
      auto current_context = core::get_current_context();
      if (!current_context) {
        log.err("no p1ll context available for auto-cure execution");
        core::cure_result result;
        result.add_error("no p1ll context available - ensure proper initialization");
        return result;
      }

      if (current_context->is_static()) {
        // static buffer patching mode
        log.inf(
            "executing static auto-cure from lua", redlog::field("name", meta.name),
            redlog::field("platforms", meta.platforms.size()), redlog::field("signatures", signatures.size()),
            redlog::field("patch_groups", patches.size())
        );

        // create cure config and execute static buffer patching
        core::cure_config config;
        config.meta = meta;
        config.signatures = signatures;
        config.patches = patches;

        // get buffer from context and patch in-place
        auto& buffer_data = current_context->get_buffer();

        engine::auto_cure_engine engine;
        return engine.execute_static_buffer(buffer_data, config);
      } else {
        // dynamic memory patching mode
        log.inf(
            "executing dynamic auto-cure from lua", redlog::field("name", meta.name),
            redlog::field("platforms", meta.platforms.size()), redlog::field("signatures", signatures.size()),
            redlog::field("patch_groups", patches.size())
        );

        // execute dynamic auto-cure
        return p1ll::auto_cure(meta, signatures, patches);
      }

    } catch (const std::exception& e) {
      log.err("auto-cure execution failed", redlog::field("error", e.what()));
      core::cure_result result;
      result.add_error("lua auto-cure failed: " + std::string(e.what()));
      return result;
    }
  });

  log.dbg("auto-cure api registered");
}

void setup_manual_api(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.manual");
  log.dbg("setting up manual api");

  // p1.get_modules(filter) - get modules matching filter
  p1_module.set_function("get_modules", [](sol::optional<sol::object> filter_opt) -> std::vector<core::module_info> {
    core::signature_query_filter filter;

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

    return p1ll::get_modules(filter);
  });

  // p1.search_signature(pattern, filter) - search for signature
  p1_module.set_function(
      "search_signature",
      [](const std::string& pattern, sol::optional<sol::object> filter_opt) -> std::vector<core::search_result> {
        core::signature_query_filter filter;

        if (filter_opt) {
          if (filter_opt->is<std::string>()) {
            // simple string filter
            filter.pattern = filter_opt->as<std::string>();
          } else if (filter_opt->is<sol::table>()) {
            // table filter for backward compatibility
            sol::table filter_table = filter_opt->as<sol::table>();
            auto region_pattern = filter_table["pattern"];
            if (region_pattern.valid() && region_pattern.is<std::string>()) {
              filter.pattern = region_pattern;
            }
          }
        }

        return p1ll::search_signature(pattern, filter);
      }
  );

  // p1.patch_memory(address, pattern) - patch memory directly
  p1_module.set_function("patch_memory", [](uint64_t address, const std::string& pattern) -> bool {
    return p1ll::patch_memory(address, pattern);
  });

  log.dbg("manual api registered");
}

void setup_utilities(sol::state& lua, sol::table& p1_module) {
  auto log = redlog::get_logger("p1ll.bindings.utilities");
  log.dbg("setting up utilities");

  // === hex utilities ===
  p1_module.set_function("str2hex", [](const std::string& str) -> std::string { return p1ll::str2hex(str); });

  p1_module.set_function("hex2str", [](const std::string& hex) -> std::string { return p1ll::hex2str(hex); });

  p1_module.set_function("format_address", [](uint64_t address) -> std::string {
    return p1ll::format_address(address);
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

} // namespace bindings

} // namespace p1ll::scripting