#pragma once

#include "thread_hook.hpp"

namespace w1::runtime::threading::hooking {

extern thread_start_interceptor g_interceptor;

bool install_platform_hooks();
void uninstall_platform_hooks();

} // namespace w1::runtime::threading::hooking
