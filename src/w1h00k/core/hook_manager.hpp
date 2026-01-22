#pragma once

#include <atomic>
#include <mutex>
#include <unordered_map>

#include "w1h00k/backend/backend_registry.hpp"
#include "w1h00k/hook.hpp"

namespace w1::h00k::core {

struct prepared_hook {
  backend::hook_plan plan{};
  backend::hook_backend* backend = nullptr;
  hook_handle handle{};
};

class hook_manager {
public:
  hook_manager();

  hook_result attach(const hook_request& request, void** original);
  hook_error detach(hook_handle handle);
  bool supports(const hook_request& request) const;

  hook_error prepare_attach(const hook_request& request, prepared_hook& out, void** original);
  hook_error prepare_detach(hook_handle handle, prepared_hook& out);
  hook_error commit_attach(prepared_hook& prepared);
  hook_error commit_detach(const prepared_hook& prepared);
  void rollback_attach(const prepared_hook& prepared);
  void rollback_detach(const prepared_hook& prepared);
  void finalize_detach(const prepared_hook& prepared);

  hook_handle reserve_handle();

  std::mutex& mutex() { return mutex_; }

private:
  bool is_valid_target(const hook_target& target) const;
  hook_technique_mask normalize_allowed(hook_technique_mask allowed) const;
  void* resolve_target(const hook_target& target) const;

  mutable std::mutex mutex_{};
  backend::backend_registry registry_{};
  std::unordered_map<uintptr_t, prepared_hook> hooks_{};
  std::unordered_map<void*, uintptr_t> target_to_handle_{};
  std::atomic<uintptr_t> next_id_{1};

  friend class hook_transaction;
};

} // namespace w1::h00k::core
