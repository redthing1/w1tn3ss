#pragma once

#include <cstdint>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <pthread.h>
#else
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace w1::util {

inline uint64_t current_thread_id() {
#if defined(_WIN32)
  return static_cast<uint64_t>(GetCurrentThreadId());
#elif defined(__APPLE__)
  return static_cast<uint64_t>(pthread_mach_thread_np(pthread_self()));
#else
  return static_cast<uint64_t>(syscall(SYS_gettid));
#endif
}

} // namespace w1::util
