#pragma once

#include "calling_convention_base.hpp"
#include "api_knowledge_db.hpp"
#include "util/module_info.hpp"
#include <regex>
#include <vector>
#include <optional>

namespace w1::abi {

/**
 * @brief detects calling conventions from symbols and module information
 *
 * supports:
 * - windows decorated names (_func@12, @func@8, etc.)
 * - module-based heuristics (kernel32.dll -> stdcall)
 * - platform defaults
 * - custom rules
 */
class calling_convention_detector {
public:
  calling_convention_detector();

  // detect convention from binary and symbol
  calling_convention_ptr detect(
      const std::string& binary_path, const std::string& symbol_name, const api_knowledge_db* api_db = nullptr
  ) const;

  // detect from module info
  calling_convention_ptr detect_from_module(
      const util::module_info& module, const std::string& symbol_name, const api_knowledge_db* api_db = nullptr
  ) const;

  // detect from symbol name alone
  calling_convention_ptr detect_from_symbol(
      const std::string& symbol_name, const api_knowledge_db* api_db = nullptr
  ) const;

  // platform-specific detection rules
  struct detection_rule {
    std::regex module_pattern;
    std::regex symbol_pattern;
    calling_convention_id convention;
    int priority = 0; // higher priority rules match first
  };

  // add custom detection rule
  void add_rule(const detection_rule& rule);

  // clear all custom rules
  void clear_rules();

  // get default convention for current platform
  calling_convention_ptr get_platform_default() const;

  // windows decorated name information
  struct decorated_info {
    calling_convention_id convention;
    size_t stack_cleanup = 0;      // bytes cleaned by callee
    bool has_this_pointer = false; // c++ member function
    std::string undecorated_name;
  };

  // parse windows decorated name
  std::optional<decorated_info> parse_decorated_name(const std::string& decorated_name) const;

private:
  std::vector<detection_rule> rules_;

  // initialize default rules
  void initialize_default_rules();

  // api database lookup
  std::optional<calling_convention_id> lookup_api_convention(
      const std::string& module_name, const std::string& symbol_name, const api_knowledge_db* api_db
  ) const;

  // windows-specific detection
  calling_convention_id detect_windows_x86(const std::string& symbol_name) const;

  calling_convention_id detect_windows_x64(const std::string& module_name) const;

  // unix-specific detection
  calling_convention_id detect_unix_convention() const;

  // arm-specific detection
  calling_convention_id detect_arm_convention() const;
};

} // namespace w1::abi