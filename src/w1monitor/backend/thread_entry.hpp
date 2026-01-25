#pragma once

#include <cstdint>

#include "w1monitor/thread_monitor.hpp"

namespace w1::monitor::backend {

template <typename InvokeFn>
uint64_t dispatch_thread_entry(thread_entry_callback& callback,
                               thread_entry_kind kind,
                               uint64_t tid,
                               void* start_routine,
                               void* arg,
                               InvokeFn invoke_start) {
  if (callback) {
    thread_entry_context ctx{};
    ctx.kind = kind;
    ctx.tid = tid;
    ctx.start_routine = start_routine;
    ctx.arg = arg;
    uint64_t callback_result = 0;
    if (callback(ctx, callback_result)) {
      return callback_result;
    }
  }
  return invoke_start();
}

} // namespace w1::monitor::backend
