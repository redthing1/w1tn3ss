#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <dlfcn.h>
#include <pthread.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include "w1monitor/monitor_factory.hpp"
#include "w1monitor/module_monitor.hpp"
#include "w1monitor/thread_monitor.hpp"

#include "test_paths.hpp"

namespace {

template <typename Event, typename Monitor, typename Predicate>
bool wait_for_event(Monitor& monitor, Event& out, Predicate predicate,
                    std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    while (monitor.poll(out)) {
      if (predicate(out)) {
        return true;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

} // namespace

int main(int argc, char** argv) {
  auto module_monitor = w1::monitor::make_module_monitor();
  auto thread_monitor = w1::monitor::make_thread_monitor();

  if (!module_monitor || !thread_monitor) {
    std::cerr << "failed to create w1monitor backends\n";
    return 1;
  }

  module_monitor->start();
  thread_monitor->start();

#if defined(_WIN32)
  constexpr const char* kLibName = "w1h00k_interpose_lib.dll";
#elif defined(__APPLE__)
  constexpr const char* kLibName = "w1h00k_interpose_lib.dylib";
#else
  constexpr const char* kLibName = "w1h00k_interpose_lib.so";
#endif

  std::string lib_path;
  if (argc > 1 && argv[1] != nullptr && argv[1][0] != '\0') {
    lib_path = argv[1];
  } else if (const char* env_path = std::getenv("W1MONITOR_DEMO_LIB")) {
    lib_path = env_path;
  } else {
    lib_path = w1::test_paths::test_library_path(kLibName);
  }

  int failures = 0;

#if defined(_WIN32)
  HMODULE lib_handle = LoadLibraryA(lib_path.c_str());
  if (!lib_handle) {
    std::cerr << "failed to load library: " << lib_path << "\n";
    failures++;
  } else {
    w1::monitor::module_event event{};
    const bool loaded = wait_for_event(
        *module_monitor, event,
        [&](const w1::monitor::module_event& e) {
          return e.type == w1::monitor::module_event::kind::loaded &&
                 !e.path.empty() && e.path.find(kLibName) != std::string::npos;
        },
        std::chrono::milliseconds(1000));
    if (loaded) {
      std::cout << "module loaded: " << event.path << "\n";
    } else {
      std::cerr << "module load not observed\n";
      failures++;
    }
  }
#else
  void* lib_handle = dlopen(lib_path.c_str(), RTLD_NOW);
  if (!lib_handle) {
    std::cerr << "failed to load library: " << lib_path << "\n";
    failures++;
  } else {
    w1::monitor::module_event event{};
    const bool loaded = wait_for_event(
        *module_monitor, event,
        [&](const w1::monitor::module_event& e) {
          return e.type == w1::monitor::module_event::kind::loaded &&
                 !e.path.empty() && e.path.find(kLibName) != std::string::npos;
        },
        std::chrono::milliseconds(1000));
    if (loaded) {
      std::cout << "module loaded: " << event.path << "\n";
    } else {
      std::cerr << "module load not observed\n";
      failures++;
    }
  }
#endif

  std::atomic<uint64_t> worker_tid{0};

#if defined(_WIN32)
  auto thread_fn = [](LPVOID param) -> DWORD {
    auto* tid_ptr = static_cast<std::atomic<uint64_t>*>(param);
    tid_ptr->store(static_cast<uint64_t>(GetCurrentThreadId()), std::memory_order_release);
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32) {
      auto set_desc = reinterpret_cast<HRESULT(WINAPI*)(HANDLE, PCWSTR)>(
          GetProcAddress(kernel32, "SetThreadDescription"));
      if (set_desc) {
        set_desc(GetCurrentThread(), L"w1mon_worker");
      }
    }
    Sleep(50);
    return 0;
  };

  HANDLE thread = CreateThread(nullptr, 0, thread_fn, &worker_tid, 0, nullptr);
  if (!thread) {
    std::cerr << "failed to create thread\n";
    failures++;
  }
#else
  std::thread worker([&]() {
#if defined(__APPLE__)
    worker_tid.store(static_cast<uint64_t>(pthread_mach_thread_np(pthread_self())),
                     std::memory_order_release);
    pthread_setname_np("w1mon_worker");
#else
    worker_tid.store(static_cast<uint64_t>(syscall(SYS_gettid)), std::memory_order_release);
    pthread_setname_np(pthread_self(), "w1mon_worker");
#endif
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  });
#endif

  bool thread_created = true;
#if defined(_WIN32)
  thread_created = (thread != nullptr);
#endif

  if (thread_created) {
    while (worker_tid.load(std::memory_order_acquire) == 0) {
      std::this_thread::yield();
    }

    const uint64_t tid = worker_tid.load(std::memory_order_acquire);
    w1::monitor::thread_event thread_event{};

    const bool saw_started = wait_for_event(
        *thread_monitor, thread_event,
        [&](const w1::monitor::thread_event& e) {
          return e.type == w1::monitor::thread_event::kind::started && e.tid == tid;
        },
        std::chrono::milliseconds(1000));
    if (saw_started) {
      std::cout << "thread started: " << thread_event.tid << "\n";
    } else {
      std::cerr << "thread start not observed\n";
      failures++;
    }

    bool expect_rename = true;
#if defined(_WIN32)
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    expect_rename = kernel32 && GetProcAddress(kernel32, "SetThreadDescription") != nullptr;
#endif

    if (expect_rename) {
      const bool saw_rename = wait_for_event(
          *thread_monitor, thread_event,
          [&](const w1::monitor::thread_event& e) {
            return e.type == w1::monitor::thread_event::kind::renamed && e.tid == tid &&
                   e.name == "w1mon_worker";
          },
          std::chrono::milliseconds(1000));
      if (saw_rename) {
        std::cout << "thread renamed: " << thread_event.name << "\n";
      } else {
        std::cerr << "thread rename not observed\n";
        failures++;
      }
    } else {
      std::cout << "thread rename not supported\n";
    }

#if defined(_WIN32)
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
#else
    worker.join();
#endif

    const bool saw_stopped = wait_for_event(
        *thread_monitor, thread_event,
        [&](const w1::monitor::thread_event& e) {
          return e.type == w1::monitor::thread_event::kind::stopped && e.tid == tid;
        },
        std::chrono::milliseconds(1000));
    if (saw_stopped) {
      std::cout << "thread stopped: " << thread_event.tid << "\n";
    } else {
      std::cerr << "thread stop not observed\n";
      failures++;
    }
  } else {
    std::cerr << "skipping thread event checks\n";
  }

#if defined(_WIN32)
  if (lib_handle) {
    FreeLibrary(lib_handle);
    w1::monitor::module_event event{};
    const bool unloaded = wait_for_event(
        *module_monitor, event,
        [&](const w1::monitor::module_event& e) {
          return e.type == w1::monitor::module_event::kind::unloaded &&
                 !e.path.empty() && e.path.find(kLibName) != std::string::npos;
        },
        std::chrono::milliseconds(1000));
    if (unloaded) {
      std::cout << "module unloaded: " << event.path << "\n";
    } else {
      std::cerr << "module unload not observed\n";
      failures++;
    }
  }
#else
  if (lib_handle) {
    dlclose(lib_handle);
    w1::monitor::module_event event{};
    const bool unloaded = wait_for_event(
        *module_monitor, event,
        [&](const w1::monitor::module_event& e) {
          return e.type == w1::monitor::module_event::kind::unloaded &&
                 !e.path.empty() && e.path.find(kLibName) != std::string::npos;
        },
        std::chrono::milliseconds(1000));
    if (unloaded) {
      std::cout << "module unloaded: " << event.path << "\n";
    } else {
      std::cerr << "module unload not observed\n";
      failures++;
    }
  }
#endif

  thread_monitor->stop();
  module_monitor->stop();

  if (failures != 0) {
    std::cerr << "monitor demo failed (" << failures << " issues)\n";
  }

  return failures == 0 ? 0 : 1;
}
