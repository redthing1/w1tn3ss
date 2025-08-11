#pragma once

#include <jnjs/jnjs.h>
#include <redlog.hpp>
#include <unordered_map>

#include "p1ll/utils/hex_utils.hpp"
#include "p1ll/core/signature.hpp"
#include "p1ll/core/types.hpp"
#include "p1ll/core/context.hpp"
#include "p1ll/engine/auto_cure.hpp"
#include "p1ll/engine/memory_scanner.hpp"

namespace p1ll::scripting::js {

using namespace jnjs;

// result wrapper classes
struct cure_result_wrapper {
  bool success;
  int patches_applied;
  int patches_failed;
  std::vector<std::string> error_messages;

  cure_result_wrapper() : success(false), patches_applied(0), patches_failed(0) {}
  cure_result_wrapper(const cure_result& result)
      : success(result.success), patches_applied(result.patches_applied), patches_failed(result.patches_failed),
        error_messages(result.error_messages) {}

  bool get_success() { return success; }
  int get_patches_applied() { return patches_applied; }
  int get_patches_failed() { return patches_failed; }
  std::vector<std::string> get_error_messages() { return error_messages; }
  bool has_errors() { return !error_messages.empty(); }

  constexpr static wrapped_class_builder<cure_result_wrapper> build_js_class() {
    wrapped_class_builder<cure_result_wrapper> builder("cure_result");
    builder.bind_function<&cure_result_wrapper::get_success>("get_success");
    builder.bind_function<&cure_result_wrapper::get_patches_applied>("get_patches_applied");
    builder.bind_function<&cure_result_wrapper::get_patches_failed>("get_patches_failed");
    builder.bind_function<&cure_result_wrapper::get_error_messages>("get_error_messages");
    builder.bind_function<&cure_result_wrapper::has_errors>("has_errors");
    return builder;
  }
};

struct search_result_wrapper {
  uint64_t address;
  std::string region_name;
  std::string section_name;

  search_result_wrapper() : address(0) {}
  search_result_wrapper(const search_result& result)
      : address(result.address), region_name(result.region_name), section_name(result.section_name) {}

  uint64_t get_address() { return address; }
  std::string get_region_name() { return region_name; }
  std::string get_section_name() { return section_name; }

  constexpr static wrapped_class_builder<search_result_wrapper> build_js_class() {
    wrapped_class_builder<search_result_wrapper> builder("search_result");
    builder.bind_function<&search_result_wrapper::get_address>("get_address");
    builder.bind_function<&search_result_wrapper::get_region_name>("get_region_name");
    builder.bind_function<&search_result_wrapper::get_section_name>("get_section_name");
    return builder;
  }
};

struct module_info_wrapper {
  std::string name;
  std::string path;
  uint64_t base_address;
  uint64_t size;
  std::string permissions;
  bool is_system_module;

  module_info_wrapper() : base_address(0), size(0), is_system_module(false) {}
  module_info_wrapper(const module_info& info)
      : name(info.name), path(info.path), base_address(info.base_address), size(info.size),
        permissions(info.permissions), is_system_module(info.is_system_module) {}

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

// signature wrapper class
struct signature_wrapper {
  signature_decl sig_decl;

  signature_wrapper() {}
  signature_wrapper(const std::string& pat) : sig_decl(pat) {}
  signature_wrapper(const signature_decl& decl) : sig_decl(decl) {}

  std::string get_pattern() { return sig_decl.pattern; }
  std::string to_string() { return sig_decl.to_string(); }

  constexpr static wrapped_class_builder<signature_wrapper> build_js_class() {
    wrapped_class_builder<signature_wrapper> builder("signature");
    builder.bind_function<&signature_wrapper::get_pattern>("get_pattern");
    builder.bind_function<&signature_wrapper::to_string>("to_string");
    return builder;
  }
};

// patch wrapper class
struct patch_wrapper {
  patch_decl patch_decl_obj;

  patch_wrapper() { patch_decl_obj.required = true; }
  patch_wrapper(signature_wrapper* sig, uint64_t off, const std::string& pattern) {
    if (sig) {
      patch_decl_obj.signature = sig->sig_decl;
    }
    patch_decl_obj.offset = off;
    patch_decl_obj.pattern = pattern;
    patch_decl_obj.required = true;
  }
  patch_wrapper(const patch_decl& decl) : patch_decl_obj(decl) {}

  signature_wrapper* get_signature() { return new signature_wrapper(patch_decl_obj.signature); }
  uint64_t get_offset() { return patch_decl_obj.offset; }
  std::string get_pattern() { return patch_decl_obj.pattern; }
  bool is_required() { return patch_decl_obj.required; }

  constexpr static wrapped_class_builder<patch_wrapper> build_js_class() {
    wrapped_class_builder<patch_wrapper> builder("patch");
    builder.bind_function<&patch_wrapper::get_signature>("get_signature");
    builder.bind_function<&patch_wrapper::get_offset>("get_offset");
    builder.bind_function<&patch_wrapper::get_pattern>("get_pattern");
    builder.bind_function<&patch_wrapper::is_required>("is_required");
    return builder;
  }
};

// main p1ll api class
struct p1ll_api {
  const p1ll::context* p1ll_ctx;
  std::vector<uint8_t>* buffer_data;
  bool dynamic_mode;

  p1ll_api(const p1ll::context* ctx, bool is_dynamic = true)
      : p1ll_ctx(ctx), buffer_data(nullptr), dynamic_mode(is_dynamic) {}
  p1ll_api(const p1ll::context* ctx, std::vector<uint8_t>* buf)
      : p1ll_ctx(ctx), buffer_data(buf), dynamic_mode(false) {}

  // utilities
  std::string str2hex(const std::string& str) { return p1ll::utils::str2hex(str); }

  std::string hex2str(const std::string& hex) { return p1ll::utils::hex2str(hex); }

  // signature creation
  signature_wrapper* sig(const std::string& pattern, std::optional<jnjs::value> options = std::nullopt) {
    if (!options || options->is<undefined>()) {
      return new signature_wrapper(pattern);
    }

    signature_query_filter filter;
    bool single = false;

    // extract filter from options
    auto filter_val = (*options)["filter"];
    if (filter_val.is<std::string>()) {
      filter.pattern = filter_val.as<std::string>();
    }

    // extract single from options
    auto single_val = (*options)["single"];
    if (single_val.is<bool>()) {
      single = single_val.as<bool>();
    }

    // create signature_decl with options
    signature_decl sig_decl(pattern, filter, single);
    return new signature_wrapper(sig_decl);
  }

  // patch creation
  patch_wrapper* patch(signature_wrapper* sig, uint64_t offset, const std::string& replace_pattern) {
    return new patch_wrapper(sig, offset, replace_pattern);
  }

  // auto_cure
  cure_result_wrapper* auto_cure(jnjs::value meta_obj);

  // get_modules with optional filter
  std::vector<module_info_wrapper*> get_modules(const std::string& filter_pattern = "") {
    auto log = redlog::get_logger("p1ll.js");

    try {
      signature_query_filter filter;
      if (!filter_pattern.empty()) {
        filter.pattern = filter_pattern;
      }

      // use memory scanner to get memory regions and convert to modules
      engine::memory_scanner scanner;
      auto regions_opt = scanner.get_memory_regions(filter);

      std::vector<module_info_wrapper*> result;
      if (regions_opt) {
        for (const auto& region : *regions_opt) {
          if (region.is_executable && !region.name.empty()) {
            // create module info from memory region
            module_info mod;
            mod.name = region.name;
            mod.path = region.name; // use name as path fallback
            mod.base_address = region.base_address;
            mod.size = region.size;
            mod.permissions = std::string("r") +
                              (has_protection(region.protection, engine::memory_protection::write) ? "w" : "-") +
                              (has_protection(region.protection, engine::memory_protection::execute) ? "x" : "-");
            mod.is_system_module = region.is_system;

            result.push_back(new module_info_wrapper(mod));
          }
        }
      }

      log.dbg("found modules", redlog::field("count", result.size()));
      return result;

    } catch (const std::exception& e) {
      log.err("get_modules failed", redlog::field("error", e.what()));
      return {};
    }
  }

  // search_sig_multiple: returns array of results
  std::vector<search_result_wrapper*> search_sig_multiple(
      const std::string& pattern, const std::string& filter_pattern = ""
  ) {
    auto log = redlog::get_logger("p1ll.js");

    try {
      // compile signature pattern
      auto compiled_sig = compile_signature(pattern);
      if (!compiled_sig) {
        log.err("failed to compile signature pattern", redlog::field("pattern", pattern));
        return {};
      }

      // create memory scanner and perform search
      engine::memory_scanner scanner;
      signature_query query;
      query.signature = *compiled_sig;
      if (!filter_pattern.empty()) {
        query.filter.pattern = filter_pattern;
      }

      auto search_results_opt = scanner.search(query);
      if (!search_results_opt) {
        log.err("search failed", redlog::field("pattern", pattern));
        return {};
      }

      std::vector<search_result_wrapper*> result;
      for (const auto& search_result : *search_results_opt) {
        result.push_back(new search_result_wrapper(search_result));
      }

      log.dbg("search completed", redlog::field("results", result.size()));
      return result;

    } catch (const std::exception& e) {
      log.err("search failed", redlog::field("error", e.what()));
      return {};
    }
  }

  // search_sig single result: returns address or 0
  uint64_t search_sig(const std::string& pattern, const std::string& filter_pattern = "") {
    auto results = search_sig_multiple(pattern, filter_pattern);
    if (results.empty()) {
      return 0;
    }
    if (results.size() > 1) {
      auto log = redlog::get_logger("p1ll.js");
      log.wrn("multiple matches, returning first", redlog::field("count", results.size()));
    }
    return results[0] ? results[0]->address : 0;
  }

  // utilities
  std::string format_address(uint64_t address) { return p1ll::utils::format_address(address); }

  // logging
  void log_info(const std::string& msg) { redlog::get_logger("p1ll.js").inf(msg); }
  void log_debug(const std::string& msg) { redlog::get_logger("p1ll.js").dbg(msg); }
  void log_warn(const std::string& msg) { redlog::get_logger("p1ll.js").wrn(msg); }
  void log_err(const std::string& msg) { redlog::get_logger("p1ll.js").err(msg); }

  constexpr static wrapped_class_builder<p1ll_api> build_js_class() {
    wrapped_class_builder<p1ll_api> builder("p1ll_api");
    builder.bind_function<&p1ll_api::str2hex>("str2hex");
    builder.bind_function<&p1ll_api::hex2str>("hex2str");
    builder.bind_function<&p1ll_api::sig>("sig");
    builder.bind_function<&p1ll_api::patch>("patch");
    builder.bind_function<&p1ll_api::auto_cure>("auto_cure");
    builder.bind_function<&p1ll_api::get_modules>("get_modules");
    builder.bind_function<&p1ll_api::search_sig>("search_sig");
    builder.bind_function<&p1ll_api::search_sig_multiple>("search_sig_multiple");
    builder.bind_function<&p1ll_api::format_address>("format_address");
    builder.bind_function<&p1ll_api::log_info>("log_info");
    builder.bind_function<&p1ll_api::log_debug>("log_debug");
    builder.bind_function<&p1ll_api::log_warn>("log_warn");
    builder.bind_function<&p1ll_api::log_err>("log_err");
    return builder;
  }
};

// helper functions for parsing js objects
inline platform_signature_map parse_signatures(const jnjs::value& meta_obj) {
  platform_signature_map sig_map;
  auto sigs_val = meta_obj["sigs"];

  if (sigs_val.is<std::unordered_map<std::string, std::vector<signature_wrapper*>>>()) {
    auto sigs_map = sigs_val.as<std::unordered_map<std::string, std::vector<signature_wrapper*>>>();
    for (const auto& [platform_key, js_sigs] : sigs_map) {
      std::vector<signature_decl> sig_decls;
      for (auto* js_sig : js_sigs) {
        if (js_sig) {
          sig_decls.push_back(js_sig->sig_decl);
        }
      }
      sig_map[platform_key] = sig_decls;
    }
  }
  return sig_map;
}

inline platform_patch_map parse_patches(const jnjs::value& meta_obj) {
  platform_patch_map patch_map;
  auto patches_val = meta_obj["patches"];

  if (patches_val.is<std::unordered_map<std::string, std::vector<patch_wrapper*>>>()) {
    auto patches_map = patches_val.as<std::unordered_map<std::string, std::vector<patch_wrapper*>>>();
    for (const auto& [platform_key, js_patches] : patches_map) {
      std::vector<patch_decl> patch_decls;
      for (auto* js_patch : js_patches) {
        if (js_patch) {
          patch_decls.push_back(js_patch->patch_decl_obj);
        }
      }
      patch_map[platform_key] = patch_decls;
    }
  }
  return patch_map;
}

inline cure_metadata parse_metadata(const jnjs::value& meta_obj) {
  cure_metadata meta;

  auto name_val = meta_obj["name"];
  if (name_val.is<std::string>()) {
    meta.name = name_val.as<std::string>();
  }

  auto platforms_val = meta_obj["platforms"];
  if (platforms_val.is<std::vector<std::string>>()) {
    meta.platforms = platforms_val.as<std::vector<std::string>>();
  }

  return meta;
}

// implementation of p1ll_api::auto_cure after helper functions
inline cure_result_wrapper* p1ll_api::auto_cure(jnjs::value meta_obj) {
  auto log = redlog::get_logger("p1ll.js.auto_cure");

  try {
    if (!p1ll_ctx) {
      log.err("no p1ll context available");
      auto result = new cure_result_wrapper();
      result->error_messages.push_back("no p1ll context");
      return result;
    }

    auto meta = parse_metadata(meta_obj);
    auto sig_map = parse_signatures(meta_obj);
    auto patch_map = parse_patches(meta_obj);

    log.inf("executing auto_cure");

    engine::auto_cure cure(*p1ll_ctx);
    cure_config config{meta, sig_map, patch_map};

    cure_result result;
    if (dynamic_mode) {
      result = cure.execute_dynamic(config);
    } else {
      result = cure.execute_static(*buffer_data, config);
    }

    return new cure_result_wrapper(result);

  } catch (const std::exception& e) {
    log.err("auto_cure failed", redlog::field("error", e.what()));
    auto result = new cure_result_wrapper();
    result->error_messages.push_back("auto_cure failed: " + std::string(e.what()));
    return result;
  }
}

inline void install_classes(jnjs::context& js_ctx) {
  js_ctx.install_class<cure_result_wrapper>();
  js_ctx.install_class<search_result_wrapper>();
  js_ctx.install_class<module_info_wrapper>();
  js_ctx.install_class<signature_wrapper>();
  js_ctx.install_class<patch_wrapper>();
  js_ctx.install_class<p1ll_api>();
}

inline void setup_p1ll_js_bindings(jnjs::context& js_ctx, const p1ll::context& p1ll_ctx) {
  auto log = redlog::get_logger("p1ll.js_bindings");
  log.inf("setting up js bindings for dynamic patching");

  install_classes(js_ctx);
  js_ctx.set_global("p1", new p1ll_api(&p1ll_ctx));

  log.inf("js bindings registered");
}

inline void setup_p1ll_js_bindings_with_buffer(
    jnjs::context& js_ctx, const p1ll::context& p1ll_ctx, std::vector<uint8_t>& buffer_data
) {
  auto log = redlog::get_logger("p1ll.js_bindings");
  log.inf("setting up js bindings for static patching");

  install_classes(js_ctx);
  js_ctx.set_global("p1", new p1ll_api(&p1ll_ctx, &buffer_data));

  log.inf("js bindings registered");
}

} // namespace p1ll::scripting::js