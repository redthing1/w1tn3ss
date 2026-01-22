#include "w1monitor/backend/darwin/darwin_thread_monitor.hpp"

#include <pthread.h>
#include <pthread/introspection.h>

#include "w1h00k/hook.hpp"
#include "w1monitor/event_queue.hpp"

namespace w1::monitor::backend::darwin {
namespace {

using pthread_setname_fn = int (*)(const char*);

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

    if (setname_handle_.id != 0) {
      (void)w1::h00k::detach(setname_handle_);
      setname_handle_ = {};
      original_setname_ = nullptr;
    }

    queue_.clear();
  }

  bool poll(thread_event& out) override { return queue_.poll(out); }

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
      thread_event event{};
      event.type = thread_event::kind::renamed;
      event.tid = static_cast<uint64_t>(pthread_mach_thread_np(pthread_self()));
      if (name) {
        event.name = name;
      }
      monitor->queue_.push(event);
    }

    if (monitor && monitor->original_setname_) {
      return monitor->original_setname_(name);
    }
    return 0;
  }

  void handle_thread_event(unsigned int event, pthread_t thread) {
    thread_event out{};
    switch (event) {
      case PTHREAD_INTROSPECTION_THREAD_START:
        out.type = thread_event::kind::started;
        break;
      case PTHREAD_INTROSPECTION_THREAD_TERMINATE:
        out.type = thread_event::kind::stopped;
        break;
      default:
        return;
    }
    out.tid = static_cast<uint64_t>(pthread_mach_thread_np(thread));
    queue_.push(out);
  }

  void install_setname_hook() {
    if (setname_handle_.id != 0) {
      return;
    }
    w1::h00k::hook_request request{};
    request.target.kind = w1::h00k::hook_target_kind::symbol;
    request.target.symbol = "pthread_setname_np";
    request.replacement = reinterpret_cast<void*>(&darwin_thread_monitor::replacement_setname);
    request.preferred = w1::h00k::hook_technique::interpose;
    request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);
    request.selection = w1::h00k::hook_selection::strict;

    void* original = nullptr;
    auto result = w1::h00k::attach(request, &original);
    if (!result.error.ok()) {
      return;
    }

    setname_handle_ = result.handle;
    original_setname_ = reinterpret_cast<pthread_setname_fn>(original);
  }

  static inline darwin_thread_monitor* active_monitor = nullptr;
  bool active_ = false;
  pthread_introspection_hook_t previous_hook_ = nullptr;
  w1::h00k::hook_handle setname_handle_{};
  pthread_setname_fn original_setname_ = nullptr;
  event_queue queue_{};
};

} // namespace

std::unique_ptr<thread_monitor> make_thread_monitor() {
  return std::make_unique<darwin_thread_monitor>();
}

} // namespace w1::monitor::backend::darwin
