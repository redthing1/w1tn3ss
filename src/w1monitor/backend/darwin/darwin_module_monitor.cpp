#include "w1monitor/backend/darwin/darwin_module_monitor.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

#include "w1monitor/event_queue.hpp"

namespace w1::monitor::backend::darwin {
namespace {

#if defined(__LP64__)
using mach_header_t = mach_header_64;
using segment_command_t = segment_command_64;
static constexpr uint32_t kSegmentCommand = LC_SEGMENT_64;
#else
using mach_header_t = mach_header;
using segment_command_t = segment_command;
static constexpr uint32_t kSegmentCommand = LC_SEGMENT;
#endif

bool macho_range(const mach_header* header, intptr_t slide, uintptr_t& base, size_t& size) {
  if (!header) {
    return false;
  }

  const auto* mh = reinterpret_cast<const mach_header_t*>(header);
  const uint8_t* cursor = reinterpret_cast<const uint8_t*>(mh) + sizeof(mach_header_t);

  uintptr_t low = UINTPTR_MAX;
  uintptr_t high = 0;
  for (uint32_t i = 0; i < mh->ncmds; ++i) {
    const auto* lc = reinterpret_cast<const load_command*>(cursor);
    if (lc->cmd == kSegmentCommand) {
      const auto* seg = reinterpret_cast<const segment_command_t*>(cursor);
      const uintptr_t seg_start = static_cast<uintptr_t>(seg->vmaddr) + static_cast<uintptr_t>(slide);
      const uintptr_t seg_end = seg_start + static_cast<uintptr_t>(seg->vmsize);
      low = std::min(low, seg_start);
      high = std::max(high, seg_end);
    }
    cursor += lc->cmdsize;
  }

  if (low == UINTPTR_MAX || high <= low) {
    return false;
  }

  base = low;
  size = high - low;
  return true;
}

class darwin_module_monitor final : public module_monitor {
public:
  darwin_module_monitor() = default;

  void start() override {
    if (active_) {
      return;
    }
    active_ = true;
    active_monitor = this;

    const uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
      const mach_header* header = _dyld_get_image_header(i);
      const intptr_t slide = _dyld_get_image_vmaddr_slide(i);
      emit_event(header, slide, module_event::kind::loaded);
    }

    _dyld_register_func_for_add_image(&darwin_module_monitor::on_image_added);
    _dyld_register_func_for_remove_image(&darwin_module_monitor::on_image_removed);
  }

  void stop() override {
    active_ = false;
    if (active_monitor == this) {
      active_monitor = nullptr;
    }
    queue_.clear();
  }

  bool poll(module_event& out) override { return queue_.poll(out); }

private:
  static void on_image_added(const mach_header* mh, intptr_t slide) {
    if (!active_monitor || !active_monitor->active_) {
      return;
    }
    active_monitor->emit_event(mh, slide, module_event::kind::loaded);
  }

  static void on_image_removed(const mach_header* mh, intptr_t slide) {
    if (!active_monitor || !active_monitor->active_) {
      return;
    }
    active_monitor->emit_event(mh, slide, module_event::kind::unloaded);
  }

  void emit_event(const mach_header* header, intptr_t slide, module_event::kind kind) {
    module_event event{};
    event.type = kind;

    Dl_info info{};
    if (header && dladdr(header, &info) != 0 && info.dli_fname) {
      event.path = info.dli_fname;
    }

    uintptr_t base = 0;
    size_t size = 0;
    if (macho_range(header, slide, base, size)) {
      event.base = reinterpret_cast<void*>(base);
      event.size = size;
    } else {
      event.base = const_cast<void*>(reinterpret_cast<const void*>(header));
      event.size = 0;
    }

    queue_.push(event);
  }

  static inline darwin_module_monitor* active_monitor = nullptr;
  bool active_ = false;
  event_queue queue_{};
};

} // namespace

std::unique_ptr<module_monitor> make_module_monitor() {
  return std::make_unique<darwin_module_monitor>();
}

} // namespace w1::monitor::backend::darwin
