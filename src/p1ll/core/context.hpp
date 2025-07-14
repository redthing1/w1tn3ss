#pragma once

#include <memory>
#include "types.hpp"

namespace p1ll {

// execution context manages execution mode and platform settings
class context {
public:
  enum class mode {
    static_buffer, // patch data in memory buffer
    dynamic_memory // patch live process memory
  };

private:
  mode operation_mode_;
  platform_key effective_platform_;

public:
  // create static context for buffer patching
  static std::unique_ptr<context> create_static();
  static std::unique_ptr<context> create_static(const platform_key& platform);

  // create dynamic context for live memory patching
  static std::unique_ptr<context> create_dynamic();

  // query context mode
  mode get_mode() const noexcept { return operation_mode_; }
  bool is_static() const noexcept { return operation_mode_ == mode::static_buffer; }
  bool is_dynamic() const noexcept { return operation_mode_ == mode::dynamic_memory; }

  // get effective platform for this context
  const platform_key& get_effective_platform() const noexcept { return effective_platform_; }

private:
  explicit context(mode op_mode, const platform_key& platform)
      : operation_mode_(op_mode), effective_platform_(platform) {}
};

} // namespace p1ll