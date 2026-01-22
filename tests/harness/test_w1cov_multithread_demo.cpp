#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32) || defined(WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#endif

#include "tracers/w1cov/coverage_engine.hpp"
#include "tracers/w1cov/coverage_tracer.hpp"
#include "w1base/thread_utils.hpp"
#include "w1formats/drcov.hpp"
#include "w1instrument/process_tracer.hpp"
#include "w1runtime/process_monitor.hpp"

#include "test_paths.hpp"

namespace {

#if defined(_WIN32) || defined(WIN32)
constexpr const char* kDemoLibraryName = "w1cov_demo_lib.dll";
using library_handle = HMODULE;
using thread_fn = DWORD(WINAPI*)(LPVOID);
#elif defined(__APPLE__)
constexpr const char* kDemoLibraryName = "w1cov_demo_lib.dylib";
using library_handle = void*;
using thread_fn = void* (*)(void*);
#else
constexpr const char* kDemoLibraryName = "w1cov_demo_lib.so";
using library_handle = void*;
using thread_fn = void* (*)(void*);
#endif

using add_fn = int (*)(int, int);
using branch_fn = int (*)(int);

struct demo_library {
  library_handle handle = nullptr;
  add_fn add = nullptr;
  branch_fn branch = nullptr;
  thread_fn thread_proc = nullptr;
};

bool load_demo_library(demo_library& out) {
  const std::string path = w1::test_paths::test_library_path(kDemoLibraryName);

#if defined(_WIN32) || defined(WIN32)
  HMODULE handle = LoadLibraryA(path.c_str());
  if (!handle) {
    std::cerr << "LoadLibrary failed for " << path << "\n";
    return false;
  }
  auto add = reinterpret_cast<add_fn>(GetProcAddress(handle, "w1cov_demo_add"));
  auto branch = reinterpret_cast<branch_fn>(GetProcAddress(handle, "w1cov_demo_branch"));
  auto thread_proc = reinterpret_cast<thread_fn>(GetProcAddress(handle, "w1cov_demo_thread_proc"));
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
  auto add = reinterpret_cast<add_fn>(dlsym(handle, "w1cov_demo_add"));
  auto branch = reinterpret_cast<branch_fn>(dlsym(handle, "w1cov_demo_branch"));
  auto thread_proc = reinterpret_cast<thread_fn>(dlsym(handle, "w1cov_demo_thread_proc"));
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

void unload_demo_library(demo_library& lib) {
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

bool run_demo_thread(thread_fn thread_proc, intptr_t value) {
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

} // namespace

int main() {
  using tracer_t = w1cov::coverage_tracer<w1cov::coverage_mode::basic_block>;

  w1cov::coverage_config config;
  config.output_file = "test_w1cov_multithread.drcov";
  config.instrumentation.include_modules = {"w1cov_demo_lib"};

  w1::runtime::process_monitor monitor;
  monitor.modules().refresh();

  auto engine = std::make_shared<w1cov::coverage_engine>(config);
  engine->configure(monitor.modules());

  w1::instrument::process_tracer<tracer_t>::config process_config{};
  process_config.instrumentation = config.instrumentation;
  process_config.attach_new_threads = true;
  process_config.refresh_on_module_events = true;
  process_config.owns_monitor = true;

  w1::instrument::process_tracer<tracer_t> process(
      monitor, process_config, [engine](const w1::runtime::thread_info&) { return tracer_t(engine); }
  );
  process.start();

  auto main_session = process.attach_current_thread("main");
  if (!main_session) {
    std::cerr << "failed to attach main session\n";
    return 1;
  }

  demo_library lib{};
  if (!load_demo_library(lib)) {
    std::cerr << "failed to load demo library\n";
    return 1;
  }

  for (int i = 0; i < 5; ++i) {
    monitor.poll_once();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }

  uint64_t result = 0;
  if (!main_session->call(reinterpret_cast<uint64_t>(lib.add), {1, 2}, &result)) {
    std::cerr << "failed to trace demo add\n";
    return 1;
  }
  if (!main_session->call(reinterpret_cast<uint64_t>(lib.branch), {42}, &result)) {
    std::cerr << "failed to trace demo branch\n";
    return 1;
  }

  if (!run_demo_thread(lib.thread_proc, 25)) {
    std::cerr << "failed to run demo thread\n";
    return 1;
  }

  main_session.reset();
  process.stop();
  unload_demo_library(lib);

  if (!engine->export_coverage()) {
    std::cerr << "coverage export produced no output\n";
    return 1;
  }

  auto data = drcov::read(config.output_file);
  if (data.basic_blocks.empty()) {
    std::cerr << "no basic blocks recorded\n";
    return 1;
  }

  bool has_module = false;
  for (const auto& module : data.modules) {
    if (module.path.find("w1cov_demo_lib") != std::string::npos) {
      has_module = true;
      break;
    }
  }
  if (!has_module) {
    std::cerr << "demo module missing from drcov output\n";
    return 1;
  }

  std::cout << "w1cov multithread demo completed\n";
  return 0;
}
