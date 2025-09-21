#include "thread_hook_internal.hpp"

#include <redlog.hpp>

namespace w1::runtime::threading::hooking {

thread_start_interceptor g_interceptor = nullptr;
namespace {
bool g_installed = false;
}

bool install(thread_start_interceptor interceptor) {
  if (g_installed) {
    return true;
  }

  g_interceptor = interceptor;
  if (!install_platform_hooks()) {
    g_interceptor = nullptr;
    return false;
  }

  g_installed = true;
  return true;
}

void uninstall() {
  if (!g_installed) {
    return;
  }

  uninstall_platform_hooks();
  g_interceptor = nullptr;
  g_installed = false;
}

bool installed() { return g_installed; }

} // namespace w1::runtime::threading::hooking
