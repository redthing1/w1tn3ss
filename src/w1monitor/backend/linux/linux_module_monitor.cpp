#include "w1monitor/backend/linux/linux_module_monitor.hpp"

#include <utility>

#include <dlfcn.h>

#include "w1h00k/hook.hpp"
#include "w1h00k/resolve/resolve.hpp"
#include "w1monitor/backend/module_snapshot.hpp"
#include "w1monitor/backend/hook_helpers.hpp"
#include "w1monitor/event_queue.hpp"

namespace w1::monitor::backend::linux_backend {
namespace {

using dlopen_fn = void* (*)(const char*, int);
using dlclose_fn = int (*)(void*);

class linux_module_monitor final : public module_monitor {
public:
  void start() override {
    if (active_) {
      return;
    }
    active_ = true;
    active_monitor = this;

    refresh_snapshot(false);
    install_hooks();
  }

  void stop() override {
    active_ = false;
    if (active_monitor == this) {
      active_monitor = nullptr;
    }

    hook_helpers::detach_if_attached(dlopen_handle_);
    original_dlopen_ = nullptr;
    hook_helpers::detach_if_attached(dlclose_handle_);
    original_dlclose_ = nullptr;

    queue_.clear();
    snapshot_.clear();
  }

  bool poll(module_event& out) override { return queue_.poll(out); }

private:
  static void* replacement_dlopen(const char* path, int mode) {
    auto* monitor = active_monitor;
    void* handle = nullptr;
    if (monitor && monitor->original_dlopen_) {
      handle = monitor->original_dlopen_(path, mode);
      if (monitor->active_) {
        monitor->refresh_snapshot(true);
      }
    }
    return handle;
  }

  static int replacement_dlclose(void* handle) {
    auto* monitor = active_monitor;
    int result = 0;
    if (monitor && monitor->original_dlclose_) {
      result = monitor->original_dlclose_(handle);
      if (monitor->active_) {
        monitor->refresh_snapshot(true);
      }
    }
    return result;
  }

  void install_hooks() {
    if (dlopen_handle_.id == 0) {
      (void)hook_helpers::attach_interpose_symbol(
          "dlopen",
          &linux_module_monitor::replacement_dlopen,
          dlopen_handle_, original_dlopen_);
    }

    if (dlclose_handle_.id == 0) {
      (void)hook_helpers::attach_interpose_symbol(
          "dlclose",
          &linux_module_monitor::replacement_dlclose,
          dlclose_handle_, original_dlclose_);
    }
  }

  void refresh_snapshot(bool emit_events) {
    const auto modules = w1::h00k::resolve::enumerate_modules();
    std::vector<module_snapshot_entry> next;
    next.reserve(modules.size());
    for (const auto& entry : modules) {
      if (!entry.base) {
        continue;
      }
      module_snapshot_entry snapshot{};
      snapshot.base = entry.base;
      snapshot.size = entry.size;
      snapshot.path = entry.path;
      next.push_back(std::move(snapshot));
    }

    snapshot_.refresh(next, emit_events, [&](const module_event& event) {
      queue_.push(event);
    });
  }

  static inline linux_module_monitor* active_monitor = nullptr;
  bool active_ = false;
  event_queue queue_{};
  module_snapshot_tracker snapshot_{};

  w1::h00k::hook_handle dlopen_handle_{};
  w1::h00k::hook_handle dlclose_handle_{};
  dlopen_fn original_dlopen_ = nullptr;
  dlclose_fn original_dlclose_ = nullptr;
};

} // namespace

std::unique_ptr<module_monitor> make_module_monitor() {
  return std::make_unique<linux_module_monitor>();
}

} // namespace w1::monitor::backend::linux_backend
