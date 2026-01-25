#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "w1monitor/backend/linux/linux_thread_monitor.hpp"

#include <atomic>
#include <cerrno>
#include <memory>

#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "w1h00k/hook.hpp"
#include "w1monitor/backend/hook_helpers.hpp"
#include "w1monitor/backend/thread_entry.hpp"
#include "w1monitor/backend/thread_event_helpers.hpp"
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

struct stop_cleanup_context {
  linux_thread_monitor* monitor = nullptr;
  uint64_t tid = 0;
  start_payload* payload = nullptr;
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

    hook_helpers::detach_if_attached(pthread_create_handle_);
    original_pthread_create_ = nullptr;
    hook_helpers::detach_if_attached(pthread_exit_handle_);
    original_pthread_exit_ = nullptr;
    hook_helpers::detach_if_attached(pthread_setname_handle_);
    original_pthread_setname_ = nullptr;

    queue_.clear();
  }

  bool poll(thread_event& out) override { return queue_.poll(out); }
  void set_entry_callback(thread_entry_callback callback) override { entry_callback_ = std::move(callback); }

private:
  static void stop_cleanup(void* arg) {
    auto* ctx = static_cast<stop_cleanup_context*>(arg);
    if (!ctx || !ctx->monitor) {
      if (ctx && ctx->payload) {
        delete ctx->payload;
      }
      return;
    }
    auto* monitor = ctx->monitor;
    if (monitor->active_ && monitor->stop_tracker_.should_emit()) {
      monitor->emitter_.stopped(ctx->tid);
    }
    if (ctx->payload) {
      delete ctx->payload;
    }
  }

  static void* start_trampoline(void* arg) {
    auto* payload = static_cast<start_payload*>(arg);
    linux_thread_monitor* monitor = payload ? payload->monitor : nullptr;
    void* (*start_routine)(void*) = payload ? payload->start_routine : nullptr;
    void* start_arg = payload ? payload->arg : nullptr;

    const uint64_t tid = current_tid();
    if (monitor && monitor->active_) {
      monitor->emitter_.started(tid);
    }
    if (monitor) {
      monitor->stop_tracker_.reset();
    }

    void* result = nullptr;
    if (monitor) {
      stop_cleanup_context cleanup{monitor, tid, payload};
      uint64_t result_value = 0;
      pthread_cleanup_push(&linux_thread_monitor::stop_cleanup, &cleanup);
      result_value = backend::dispatch_thread_entry(
          monitor->entry_callback_,
          thread_entry_kind::posix,
          tid,
          reinterpret_cast<void*>(start_routine),
          start_arg,
          [&]() -> uint64_t {
            if (start_routine) {
              return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(start_routine(start_arg)));
            }
            return 0;
          });
      pthread_cleanup_pop(0);
      result = reinterpret_cast<void*>(static_cast<uintptr_t>(result_value));
      delete payload;
    } else if (start_routine) {
      result = start_routine(start_arg);
      if (payload) {
        delete payload;
      }
    } else if (payload) {
      delete payload;
    }

    if (monitor && monitor->active_ && monitor->stop_tracker_.should_emit()) {
      monitor->emitter_.stopped(tid);
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
    if (monitor && monitor->active_ && monitor->stop_tracker_.should_emit()) {
      monitor->emitter_.stopped(current_tid());
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
      monitor->emitter_.renamed(current_tid(), name);
    }
    return result;
  }

  void install_hooks() {
    if (pthread_create_handle_.id == 0) {
      (void)hook_helpers::attach_symbol_replace_prefer_inline(
          "pthread_create",
          nullptr,
          &linux_thread_monitor::replacement_pthread_create,
          pthread_create_handle_, original_pthread_create_);
    }

    if (pthread_exit_handle_.id == 0) {
      (void)hook_helpers::attach_symbol_replace_prefer_inline(
          "pthread_exit",
          nullptr,
          &linux_thread_monitor::replacement_pthread_exit,
          pthread_exit_handle_, original_pthread_exit_);
    }

    if (pthread_setname_handle_.id == 0) {
      (void)hook_helpers::attach_symbol_replace_prefer_inline(
          "pthread_setname_np",
          nullptr,
          &linux_thread_monitor::replacement_pthread_setname,
          pthread_setname_handle_, original_pthread_setname_);
    }
  }

  static inline linux_thread_monitor* active_monitor = nullptr;
  bool active_ = false;
  event_queue queue_{};
  thread_event_emitter emitter_{queue_};
  thread_stop_tracker stop_tracker_{};

  w1::h00k::hook_handle pthread_create_handle_{};
  w1::h00k::hook_handle pthread_exit_handle_{};
  w1::h00k::hook_handle pthread_setname_handle_{};

  pthread_create_fn original_pthread_create_ = nullptr;
  pthread_exit_fn original_pthread_exit_ = nullptr;
  pthread_setname_fn original_pthread_setname_ = nullptr;
  thread_entry_callback entry_callback_{};
};

} // namespace

std::unique_ptr<thread_monitor> make_thread_monitor() {
  return std::make_unique<linux_thread_monitor>();
}

} // namespace w1::monitor::backend::linux_backend
