#include "w1monitor/backend/linux/linux_module_monitor.hpp"

#include <mutex>
#include <unordered_map>
#include <utility>

#include <dlfcn.h>

#include "w1h00k/hook.hpp"
#include "w1h00k/resolve/resolve.hpp"
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

    if (dlopen_handle_.id != 0) {
      (void)w1::h00k::detach(dlopen_handle_);
      dlopen_handle_ = {};
      original_dlopen_ = nullptr;
    }
    if (dlclose_handle_.id != 0) {
      (void)w1::h00k::detach(dlclose_handle_);
      dlclose_handle_ = {};
      original_dlclose_ = nullptr;
    }

    queue_.clear();
    std::lock_guard<std::mutex> lock(modules_mutex_);
    modules_.clear();
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
    if (dlopen_handle_.id != 0 || dlclose_handle_.id != 0) {
      return;
    }

    w1::h00k::hook_request dlopen_request{};
    dlopen_request.target.kind = w1::h00k::hook_target_kind::symbol;
    dlopen_request.target.symbol = "dlopen";
    dlopen_request.replacement = reinterpret_cast<void*>(&linux_module_monitor::replacement_dlopen);
    dlopen_request.preferred = w1::h00k::hook_technique::interpose;
    dlopen_request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);
    dlopen_request.selection = w1::h00k::hook_selection::strict;

    void* original = nullptr;
    auto dlopen_result = w1::h00k::attach(dlopen_request, &original);
    if (dlopen_result.error.ok()) {
      dlopen_handle_ = dlopen_result.handle;
      original_dlopen_ = reinterpret_cast<dlopen_fn>(original);
    }

    w1::h00k::hook_request dlclose_request{};
    dlclose_request.target.kind = w1::h00k::hook_target_kind::symbol;
    dlclose_request.target.symbol = "dlclose";
    dlclose_request.replacement = reinterpret_cast<void*>(&linux_module_monitor::replacement_dlclose);
    dlclose_request.preferred = w1::h00k::hook_technique::interpose;
    dlclose_request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);
    dlclose_request.selection = w1::h00k::hook_selection::strict;

    original = nullptr;
    auto dlclose_result = w1::h00k::attach(dlclose_request, &original);
    if (dlclose_result.error.ok()) {
      dlclose_handle_ = dlclose_result.handle;
      original_dlclose_ = reinterpret_cast<dlclose_fn>(original);
    }
  }

  void refresh_snapshot(bool emit_events) {
    const auto modules = w1::h00k::resolve::enumerate_modules();
    std::unordered_map<void*, w1::h00k::resolve::module_info> next;
    next.reserve(modules.size());
    for (const auto& entry : modules) {
      if (!entry.base) {
        continue;
      }
      next[entry.base] = entry;
    }

    std::lock_guard<std::mutex> lock(modules_mutex_);
    if (emit_events) {
      for (const auto& [base, info] : next) {
        if (modules_.find(base) == modules_.end()) {
          module_event event{};
          event.type = module_event::kind::loaded;
          event.path = info.path;
          event.base = info.base;
          event.size = info.size;
          queue_.push(event);
        }
      }

      for (const auto& [base, info] : modules_) {
        if (next.find(base) == next.end()) {
          module_event event{};
          event.type = module_event::kind::unloaded;
          event.path = info.path;
          event.base = info.base;
          event.size = info.size;
          queue_.push(event);
        }
      }
    }

    modules_ = std::move(next);
  }

  static inline linux_module_monitor* active_monitor = nullptr;
  bool active_ = false;
  event_queue queue_{};
  std::mutex modules_mutex_{};
  std::unordered_map<void*, w1::h00k::resolve::module_info> modules_{};

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
