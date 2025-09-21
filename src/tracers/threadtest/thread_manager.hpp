#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

#include <QBDI.h>
#include <redlog.hpp>

#include "thread_context.hpp"
#include "threadtest_config.hpp"

namespace threadtest {

class thread_manager {
public:
  static thread_manager& instance();

  void configure(const threadtest_config& config);

  thread_context* register_main_thread(QBDI::VMInstanceRef vm);

  thread_context* attach_thread(uint64_t native_id, const std::string& name);
  void detach_thread(uint64_t native_id);

  thread_context* tls_context() const;
  void set_tls_context(thread_context* context) const;

  const threadtest_config& config() const { return config_; }
  bool is_configured() const { return configured_; }
  bool thread_hooks_enabled() const { return config_.enable_thread_hooks; }

  std::optional<uint64_t> get_current_thread_id() const;

private:
  thread_manager() = default;

  uint64_t next_thread_id_ = 1;
  bool configured_ = false;

  threadtest_config config_;

  mutable std::mutex mutex_;
  std::unordered_map<uint64_t, std::unique_ptr<thread_context>> contexts_;
  std::unordered_map<uint64_t, uint64_t> thread_id_by_native_;

  redlog::logger log_ = redlog::get_logger("threadtest.manager");

  uint64_t allocate_thread_id();
};

} // namespace threadtest
