#pragma once

#include <vector>
#include <optional>
#include <functional>
#include <memory>
#include "platform.hpp"

namespace p1ll::core {

// p1ll execution context - manages static vs dynamic mode
class p1ll_context {
public:
  enum class mode {
    static_buffer, // patch data in memory buffer
    dynamic_memory // patch live process memory
  };

private:
  mode operation_mode_;
  std::optional<std::reference_wrapper<std::vector<uint8_t>>> buffer_data_;
  platform_key effective_platform_;

  // prevent copying to avoid reference issues
  p1ll_context(const p1ll_context&) = delete;
  p1ll_context& operator=(const p1ll_context&) = delete;

public:
  // create static context for buffer patching
  static std::unique_ptr<p1ll_context> create_static(std::vector<uint8_t>& buffer);
  static std::unique_ptr<p1ll_context> create_static(std::vector<uint8_t>& buffer, const platform_key& platform);

  // create dynamic context for live memory patching
  static std::unique_ptr<p1ll_context> create_dynamic();

  // query context mode
  mode get_mode() const noexcept { return operation_mode_; }
  bool is_static() const noexcept { return operation_mode_ == mode::static_buffer; }
  bool is_dynamic() const noexcept { return operation_mode_ == mode::dynamic_memory; }

  // get buffer for static mode (throws if dynamic mode)
  std::vector<uint8_t>& get_buffer() const;

  // get effective platform for this context
  const platform_key& get_effective_platform() const noexcept { return effective_platform_; }

private:
  explicit p1ll_context(mode op_mode, const platform_key& platform)
      : operation_mode_(op_mode), effective_platform_(platform) {}
  explicit p1ll_context(mode op_mode, std::vector<uint8_t>& buffer, const platform_key& platform)
      : operation_mode_(op_mode), buffer_data_(std::ref(buffer)), effective_platform_(platform) {}
};

// global context management for lua bindings
void set_current_context(std::unique_ptr<p1ll_context> context);
p1ll_context* get_current_context();
void clear_current_context();

} // namespace p1ll::core