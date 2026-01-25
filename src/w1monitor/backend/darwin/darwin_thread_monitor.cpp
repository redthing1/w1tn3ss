#include "w1monitor/backend/darwin/darwin_thread_monitor.hpp"

#include <cerrno>
#include <memory>
#include <pthread.h>
#include <pthread/introspection.h>

#include "w1h00k/hook.hpp"
#include "w1monitor/backend/hook_helpers.hpp"
#include "w1monitor/backend/thread_entry.hpp"
#include "w1monitor/backend/thread_event_helpers.hpp"
#include "w1monitor/event_queue.hpp"

namespace w1::monitor::backend::darwin {
namespace {

using pthread_setname_fn = int (*)(const char*);
using pthread_create_fn = int (*)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);

struct start_payload {
  void* (*start_routine)(void*) = nullptr;
  void* arg = nullptr;
  class darwin_thread_monitor* monitor = nullptr;
};

class darwin_thread_monitor final : public thread_monitor {
public:
  darwin_thread_monitor() = default;

  void start() override {
    if (active_) {
      return;
    }
    active_ = true;
    active_monitor = this;

    previous_hook_ = pthread_introspection_hook_install(&darwin_thread_monitor::on_thread_event);

    install_setname_hook();
    install_create_hook();
  }

  void stop() override {
    active_ = false;
    if (active_monitor == this) {
      active_monitor = nullptr;
    }

    if (previous_hook_) {
      (void)pthread_introspection_hook_install(previous_hook_);
      previous_hook_ = nullptr;
    }

    hook_helpers::detach_if_attached(setname_handle_);
    original_setname_ = nullptr;
    hook_helpers::detach_if_attached(create_handle_);
    original_create_ = nullptr;

    queue_.clear();
  }

  bool poll(thread_event& out) override { return queue_.poll(out); }
  void set_entry_callback(thread_entry_callback callback) override { entry_callback_ = std::move(callback); }

private:
  static void on_thread_event(unsigned int event, pthread_t thread, void* addr, size_t size) {
    if (active_monitor && active_monitor->active_) {
      active_monitor->handle_thread_event(event, thread);
    }

    if (active_monitor && active_monitor->previous_hook_) {
      active_monitor->previous_hook_(event, thread, addr, size);
    }
  }

  static int replacement_setname(const char* name) {
    darwin_thread_monitor* monitor = active_monitor;
    if (monitor && monitor->active_) {
      monitor->emitter_.renamed(static_cast<uint64_t>(pthread_mach_thread_np(pthread_self())),
                                name ? std::string_view(name) : std::string_view{});
    }

    if (monitor && monitor->original_setname_) {
      return monitor->original_setname_(name);
    }
    return 0;
  }

  static void* start_trampoline(void* arg) {
    std::unique_ptr<start_payload> payload(static_cast<start_payload*>(arg));
    darwin_thread_monitor* monitor = payload->monitor;
    void* (*start_routine)(void*) = payload->start_routine;
    void* start_arg = payload->arg;

    void* result = nullptr;
    if (monitor) {
      const uint64_t result_value = backend::dispatch_thread_entry(
          monitor->entry_callback_,
          thread_entry_kind::posix,
          static_cast<uint64_t>(pthread_mach_thread_np(pthread_self())),
          reinterpret_cast<void*>(start_routine),
          start_arg,
          [&]() -> uint64_t {
            if (start_routine) {
              return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(start_routine(start_arg)));
            }
            return 0;
          });
      result = reinterpret_cast<void*>(static_cast<uintptr_t>(result_value));
    } else if (start_routine) {
      result = start_routine(start_arg);
    }

    return result;
  }

  static int replacement_pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                                        void* (*start_routine)(void*), void* arg) {
    auto* monitor = active_monitor;
    if (!monitor || !monitor->original_create_) {
      return EINVAL;
    }

    auto* payload = new start_payload{};
    payload->start_routine = start_routine;
    payload->arg = arg;
    payload->monitor = monitor;

    const int result = monitor->original_create_(thread, attr, &darwin_thread_monitor::start_trampoline, payload);
    if (result != 0) {
      delete payload;
    }
    return result;
  }

  void handle_thread_event(unsigned int event, pthread_t thread) {
    switch (event) {
      case PTHREAD_INTROSPECTION_THREAD_START:
        emitter_.started(static_cast<uint64_t>(pthread_mach_thread_np(thread)));
        break;
      case PTHREAD_INTROSPECTION_THREAD_TERMINATE:
        emitter_.stopped(static_cast<uint64_t>(pthread_mach_thread_np(thread)));
        break;
      default:
        return;
    }
  }

  void install_setname_hook() {
    if (setname_handle_.id != 0) {
      return;
    }
    if (!hook_helpers::attach_interpose_symbol(
            "pthread_setname_np",
            &darwin_thread_monitor::replacement_setname,
            setname_handle_, original_setname_)) {
      return;
    }
  }

  void install_create_hook() {
    if (create_handle_.id != 0) {
      return;
    }
    if (!hook_helpers::attach_interpose_symbol(
            "pthread_create",
            &darwin_thread_monitor::replacement_pthread_create,
            create_handle_, original_create_)) {
      return;
    }
  }

  static inline darwin_thread_monitor* active_monitor = nullptr;
  bool active_ = false;
  pthread_introspection_hook_t previous_hook_ = nullptr;
  w1::h00k::hook_handle setname_handle_{};
  w1::h00k::hook_handle create_handle_{};
  pthread_setname_fn original_setname_ = nullptr;
  pthread_create_fn original_create_ = nullptr;
  event_queue queue_{};
  thread_event_emitter emitter_{queue_};
  thread_entry_callback entry_callback_{};
};

} // namespace

std::unique_ptr<thread_monitor> make_thread_monitor() {
  return std::make_unique<darwin_thread_monitor>();
}

} // namespace w1::monitor::backend::darwin
