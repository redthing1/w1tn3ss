#pragma once

#include <cstdint>

namespace w1 {

enum class event_kind : uint32_t {
  instruction_pre = 0,
  instruction_post,
  basic_block_entry,
  basic_block_exit,
  memory_read,
  memory_write,
  memory_read_write,
  exec_transfer_call,
  exec_transfer_return,
  vm_start,
  vm_stop,
  thread_start,
  thread_stop
};

using event_mask = uint64_t;

constexpr event_mask event_mask_of(event_kind kind) {
  return event_mask{1} << static_cast<event_mask>(kind);
}

constexpr bool event_mask_has(event_mask mask, event_kind kind) {
  return (mask & event_mask_of(kind)) != 0;
}

constexpr event_mask event_mask_or(event_mask left, event_mask right) { return left | right; }

} // namespace w1
