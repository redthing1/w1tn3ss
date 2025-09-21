#pragma once

#include <cstdint>

namespace threadtest {

using thread_start_fn = void* (*) (void*);
using thread_start_interceptor = void* (*) (thread_start_fn, void*);

namespace hooking {

bool install(thread_start_interceptor interceptor);
void uninstall();
bool installed();

} // namespace hooking

} // namespace threadtest
