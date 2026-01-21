#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

threads_component::threads_component(const adapter_services& services, thread_state& thread)
    : services_(services), thread_(thread) {}

std::vector<uint64_t> threads_component::thread_ids() const { return {thread_.active_thread_id}; }

uint64_t threads_component::current_thread() const { return thread_.active_thread_id; }

gdbstub::target_status threads_component::set_current_thread(uint64_t) { return gdbstub::target_status::unsupported; }

std::optional<uint64_t> threads_component::thread_pc(uint64_t tid) const {
  if (tid != thread_.active_thread_id) {
    return std::nullopt;
  }
  if (!services_.session) {
    return std::nullopt;
  }
  return services_.session->current_step().address;
}

std::optional<std::string> threads_component::thread_name(uint64_t tid) const {
  if (!services_.context) {
    return std::nullopt;
  }
  for (const auto& info : services_.context->threads) {
    if (info.thread_id == tid) {
      return info.name;
    }
  }
  return std::nullopt;
}

std::optional<gdbstub::stop_reason> threads_component::thread_stop_reason(uint64_t tid) const {
  if (tid != thread_.active_thread_id) {
    return std::nullopt;
  }
  return thread_.last_stop;
}

} // namespace w1replay::gdb
