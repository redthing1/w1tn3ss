#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "w1monitor/backend/linux/linux_thread_monitor.hpp"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <memory>
#include <mutex>

#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "w1h00k/hook.hpp"
#include "w1monitor/event_queue.hpp"

namespace w1::monitor::backend::linux_backend {
namespace {

using pthread_create_fn = int (*)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
using pthread_exit_fn = void (*)(void*);
using pthread_setname_fn = int (*)(pthread_t, const char*);

uint64_t current_tid() {
  return static_cast<uint64_t>(syscall(SYS_gettid));
}

struct start_payload {
  void* (*start_routine)(void*) = nullptr;
  void* arg = nullptr;
  class linux_thread_monitor* monitor = nullptr;
};

class linux_thread_monitor final : public thread_monitor {
public:
  void start() override {
    if (active_) {
      return;
    }
    active_ = true;
    active_monitor = this;

    install_hooks();
  }

  void stop() override {
    active_ = false;
    if (active_monitor == this) {
      active_monitor = nullptr;
    }

    if (pthread_create_handle_.id != 0) {
      (void)w1::h00k::detach(pthread_create_handle_);
      pthread_create_handle_ = {};
      original_pthread_create_ = nullptr;
    }
    if (pthread_exit_handle_.id != 0) {
      (void)w1::h00k::detach(pthread_exit_handle_);
      pthread_exit_handle_ = {};
      original_pthread_exit_ = nullptr;
    }
    if (pthread_setname_handle_.id != 0) {
      (void)w1::h00k::detach(pthread_setname_handle_);
      pthread_setname_handle_ = {};
      original_pthread_setname_ = nullptr;
    }

    queue_.clear();
  }

  bool poll(thread_event& out) override { return queue_.poll(out); }

private:
  static void* start_trampoline(void* arg) {
    std::unique_ptr<start_payload> payload(static_cast<start_payload*>(arg));
    linux_thread_monitor* monitor = payload->monitor;
    void* (*start_routine)(void*) = payload->start_routine;
    void* start_arg = payload->arg;

    if (monitor && monitor->active_) {
      monitor->emit_started(current_tid());
    }

    void* result = nullptr;
    if (start_routine) {
      result = start_routine(start_arg);
    }

    if (monitor && monitor->active_) {
      monitor->emit_stopped(current_tid());
    }

    return result;
  }

  static int replacement_pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                                        void* (*start_routine)(void*), void* arg) {
    auto* monitor = active_monitor;
    if (!monitor || !monitor->original_pthread_create_) {
      return EINVAL;
    }

    auto* payload = new start_payload{};
    payload->start_routine = start_routine;
    payload->arg = arg;
    payload->monitor = monitor;

    const int result =
        monitor->original_pthread_create_(thread, attr, &linux_thread_monitor::start_trampoline, payload);
    if (result != 0) {
      delete payload;
    }
    return result;
  }

  static void replacement_pthread_exit(void* value) {
    auto* monitor = active_monitor;
    if (monitor && monitor->active_) {
      monitor->emit_stopped(current_tid());
    }
    if (monitor && monitor->original_pthread_exit_) {
      monitor->original_pthread_exit_(value);
    }
  }

  static int replacement_pthread_setname(pthread_t thread, const char* name) {
    auto* monitor = active_monitor;
    int result = 0;
    if (monitor && monitor->original_pthread_setname_) {
      result = monitor->original_pthread_setname_(thread, name);
    }
    if (monitor && monitor->active_ && result == 0 && name &&
        pthread_equal(thread, pthread_self())) {
      monitor->emit_renamed(current_tid(), name);
    }
    return result;
  }

  void install_hooks() {
    if (pthread_create_handle_.id != 0) {
      return;
    }

    w1::h00k::hook_request create_request{};
    create_request.target.kind = w1::h00k::hook_target_kind::symbol;
    create_request.target.symbol = "pthread_create";
    create_request.replacement = reinterpret_cast<void*>(&linux_thread_monitor::replacement_pthread_create);
    create_request.preferred = w1::h00k::hook_technique::interpose;
    create_request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);
    create_request.selection = w1::h00k::hook_selection::strict;

    void* original = nullptr;
    auto create_result = w1::h00k::attach(create_request, &original);
    if (create_result.error.ok()) {
      pthread_create_handle_ = create_result.handle;
      original_pthread_create_ = reinterpret_cast<pthread_create_fn>(original);
    }

    w1::h00k::hook_request exit_request{};
    exit_request.target.kind = w1::h00k::hook_target_kind::symbol;
    exit_request.target.symbol = "pthread_exit";
    exit_request.replacement = reinterpret_cast<void*>(&linux_thread_monitor::replacement_pthread_exit);
    exit_request.preferred = w1::h00k::hook_technique::interpose;
    exit_request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);
    exit_request.selection = w1::h00k::hook_selection::strict;

    original = nullptr;
    auto exit_result = w1::h00k::attach(exit_request, &original);
    if (exit_result.error.ok()) {
      pthread_exit_handle_ = exit_result.handle;
      original_pthread_exit_ = reinterpret_cast<pthread_exit_fn>(original);
    }

    w1::h00k::hook_request setname_request{};
    setname_request.target.kind = w1::h00k::hook_target_kind::symbol;
    setname_request.target.symbol = "pthread_setname_np";
    setname_request.replacement = reinterpret_cast<void*>(&linux_thread_monitor::replacement_pthread_setname);
    setname_request.preferred = w1::h00k::hook_technique::interpose;
    setname_request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);
    setname_request.selection = w1::h00k::hook_selection::strict;

    original = nullptr;
    auto setname_result = w1::h00k::attach(setname_request, &original);
    if (setname_result.error.ok()) {
      pthread_setname_handle_ = setname_result.handle;
      original_pthread_setname_ = reinterpret_cast<pthread_setname_fn>(original);
    }
  }

  void emit_started(uint64_t tid) {
    thread_event event{};
    event.type = thread_event::kind::started;
    event.tid = tid;
    queue_.push(event);
  }

  void emit_stopped(uint64_t tid) {
    thread_event event{};
    event.type = thread_event::kind::stopped;
    event.tid = tid;
    queue_.push(event);
  }

  void emit_renamed(uint64_t tid, const char* name) {
    thread_event event{};
    event.type = thread_event::kind::renamed;
    event.tid = tid;
    event.name = name;
    queue_.push(event);
  }

  static inline linux_thread_monitor* active_monitor = nullptr;
  bool active_ = false;
  event_queue queue_{};

  w1::h00k::hook_handle pthread_create_handle_{};
  w1::h00k::hook_handle pthread_exit_handle_{};
  w1::h00k::hook_handle pthread_setname_handle_{};

  pthread_create_fn original_pthread_create_ = nullptr;
  pthread_exit_fn original_pthread_exit_ = nullptr;
  pthread_setname_fn original_pthread_setname_ = nullptr;
};

} // namespace

std::unique_ptr<thread_monitor> make_thread_monitor() {
  return std::make_unique<linux_thread_monitor>();
}

} // namespace w1::monitor::backend::linux_backend
