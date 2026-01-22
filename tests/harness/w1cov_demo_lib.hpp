#pragma once

#include <cstdint>
#include <iostream>
#include <string>

#if defined(_WIN32) || defined(WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#endif

#include "test_paths.hpp"

namespace w1::test_helpers {

#if defined(_WIN32) || defined(WIN32)
constexpr const char* demo_library_name = "w1cov_demo_lib.dll";
using demo_library_handle = HMODULE;
using demo_thread_fn = DWORD(WINAPI*)(LPVOID);
#elif defined(__APPLE__)
constexpr const char* demo_library_name = "w1cov_demo_lib.dylib";
using demo_library_handle = void*;
using demo_thread_fn = void* (*)(void*);
#else
constexpr const char* demo_library_name = "w1cov_demo_lib.so";
using demo_library_handle = void*;
using demo_thread_fn = void* (*)(void*);
#endif

using demo_add_fn = int (*)(int, int);
using demo_branch_fn = int (*)(int);

struct demo_library {
  demo_library_handle handle = nullptr;
  demo_add_fn add = nullptr;
  demo_branch_fn branch = nullptr;
  demo_thread_fn thread_proc = nullptr;
};

inline bool load_demo_library(demo_library& out) {
  const std::string path = w1::test_paths::test_library_path(demo_library_name);

#if defined(_WIN32) || defined(WIN32)
  HMODULE handle = LoadLibraryA(path.c_str());
  if (!handle) {
    std::cerr << "LoadLibrary failed for " << path << "\n";
    return false;
  }
  auto add = reinterpret_cast<demo_add_fn>(GetProcAddress(handle, "w1cov_demo_add"));
  auto branch = reinterpret_cast<demo_branch_fn>(GetProcAddress(handle, "w1cov_demo_branch"));
  auto thread_proc = reinterpret_cast<demo_thread_fn>(GetProcAddress(handle, "w1cov_demo_thread_proc"));
  if (!add || !branch || !thread_proc) {
    std::cerr << "GetProcAddress failed for demo library exports\n";
    FreeLibrary(handle);
    return false;
  }
  out.handle = handle;
  out.add = add;
  out.branch = branch;
  out.thread_proc = thread_proc;
  return true;
#else
  void* handle = dlopen(path.c_str(), RTLD_NOW);
  if (!handle) {
    std::cerr << "dlopen failed for " << path << ": " << dlerror() << "\n";
    return false;
  }
  dlerror();
  auto add = reinterpret_cast<demo_add_fn>(dlsym(handle, "w1cov_demo_add"));
  auto branch = reinterpret_cast<demo_branch_fn>(dlsym(handle, "w1cov_demo_branch"));
  auto thread_proc = reinterpret_cast<demo_thread_fn>(dlsym(handle, "w1cov_demo_thread_proc"));
  if (!add || !branch || !thread_proc) {
    std::cerr << "dlsym failed for demo library exports\n";
    dlclose(handle);
    return false;
  }
  out.handle = handle;
  out.add = add;
  out.branch = branch;
  out.thread_proc = thread_proc;
  return true;
#endif
}

inline void unload_demo_library(demo_library& lib) {
  if (!lib.handle) {
    return;
  }
#if defined(_WIN32) || defined(WIN32)
  FreeLibrary(lib.handle);
#else
  dlclose(lib.handle);
#endif
  lib.handle = nullptr;
}

inline bool run_demo_thread(demo_thread_fn thread_proc, intptr_t value) {
#if defined(_WIN32) || defined(WIN32)
  HANDLE thread = CreateThread(nullptr, 0, thread_proc, reinterpret_cast<void*>(value), 0, nullptr);
  if (!thread) {
    return false;
  }
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);
  return true;
#else
  pthread_t thread{};
  if (pthread_create(&thread, nullptr, thread_proc, reinterpret_cast<void*>(value)) != 0) {
    return false;
  }
  pthread_join(thread, nullptr);
  return true;
#endif
}

} // namespace w1::test_helpers
