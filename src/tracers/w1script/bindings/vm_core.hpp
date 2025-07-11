#pragma once

#include <sol/sol.hpp>
#include <memory>
#include <vector>
#include <mutex>

namespace w1::tracers::script::bindings {

// Callback storage that can be cleaned up properly
class vm_callback_storage {
public:
  static vm_callback_storage& instance();

  size_t store_callback(sol::protected_function callback);
  sol::protected_function* get_callback(size_t idx);
  void clear_all_callbacks();

private:
  vm_callback_storage() = default;
  std::mutex mutex_;
  std::vector<sol::protected_function> callbacks_;
};

/**
 * Setup core QBDI VM bindings for direct VM manipulation
 * This exposes the low-level VM API for advanced scripts that need
 * direct control over instrumentation, caching, and VM state.
 *
 * @param lua       The Lua state
 * @param w1_module The w1 module table to add bindings to
 */
void setup_vm_core(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings