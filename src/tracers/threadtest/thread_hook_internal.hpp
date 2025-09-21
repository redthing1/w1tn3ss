#pragma once

#include "thread_hook.hpp"

namespace threadtest::hooking {

extern thread_start_interceptor g_interceptor;

bool install_platform_hooks();
void uninstall_platform_hooks();

} // namespace threadtest::hooking
