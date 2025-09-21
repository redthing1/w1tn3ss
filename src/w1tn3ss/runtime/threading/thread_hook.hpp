#pragma once

#include <cstdint>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace w1::runtime::threading {

#if defined(_WIN32)
using thread_result_t = DWORD;
using thread_start_fn = DWORD(WINAPI*)(void*);
#else
using thread_result_t = void*;
using thread_start_fn = void* (*) (void*);
#endif

using thread_start_interceptor = thread_result_t (*)(thread_start_fn, void*);

namespace hooking {

bool install(thread_start_interceptor interceptor);
void uninstall();
bool installed();

} // namespace hooking

} // namespace w1::runtime::threading
