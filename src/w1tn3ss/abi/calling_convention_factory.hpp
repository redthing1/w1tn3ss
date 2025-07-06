#pragma once

#include "calling_convention_base.hpp"
#include <unordered_map>
#include <mutex>
#include <functional>
#include <redlog.hpp>

namespace w1::abi {

// factory for creating calling convention instances
class calling_convention_factory {
public:
  // singleton instance
  static calling_convention_factory& instance();

  // prevent copying
  calling_convention_factory(const calling_convention_factory&) = delete;
  calling_convention_factory& operator=(const calling_convention_factory&) = delete;

  // register a convention creator
  void register_convention(calling_convention_id id, std::function<calling_convention_ptr()> creator);

  // create convention by id
  calling_convention_ptr create(calling_convention_id id) const;

  // create convention by name
  calling_convention_ptr create_by_name(const std::string& name) const;

  // get default convention for current platform
  calling_convention_ptr create_default() const;

  // list all registered conventions
  std::vector<calling_convention_id> list_conventions() const;

  // get convention for a specific module/function
  calling_convention_ptr create_for_symbol(const std::string& module_name, const std::string& symbol_name) const;

  // check if convention is registered
  bool is_registered(calling_convention_id id) const;

private:
  calling_convention_factory() : log_("w1.calling_convention_factory") {}

  mutable std::mutex mutex_;
  std::unordered_map<calling_convention_id, std::function<calling_convention_ptr()>> creators_;
  std::unordered_map<std::string, calling_convention_id> name_to_id_;
  redlog::logger log_;

  // platform-specific default selection
  calling_convention_id get_platform_default() const;

  // register all conventions for current platform
  void register_platform_conventions();

  // register specific platform conventions
  void register_x86_conventions();
  void register_x86_64_conventions();
  void register_arm_conventions();
  void register_arm64_conventions();
};

// convenience function
inline calling_convention_ptr create_calling_convention(calling_convention_id id) {
  return calling_convention_factory::instance().create(id);
}

// convenience function for default convention
inline calling_convention_ptr create_default_calling_convention() {
  return calling_convention_factory::instance().create_default();
}

} // namespace w1::abi