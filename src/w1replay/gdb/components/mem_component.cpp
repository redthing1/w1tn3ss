#include "w1replay/gdb/adapter_components.hpp"

#include <algorithm>

#include "w1replay/memory/memory_view.hpp"

namespace w1replay::gdb {

mem_component::mem_component(const adapter_services& services) : services_(services) {}

gdbstub::target_status mem_component::read_mem(uint64_t addr, std::span<std::byte> out) {
  if (!services_.memory) {
    return gdbstub::target_status::unsupported;
  }

  auto read = services_.memory->read(addr, out.size());
  if (read.bytes.size() < out.size()) {
    return gdbstub::target_status::fault;
  }
  std::copy(read.bytes.begin(), read.bytes.begin() + static_cast<std::ptrdiff_t>(out.size()), out.begin());

  if (read.complete() || read.any_known()) {
    // lldb issues aligned reads that can extend beyond recorded snapshot windows
    // return best-effort data when any bytes are known so the debugger keeps the
    // valid portion instead of treating the whole read as unavailable
    return gdbstub::target_status::ok;
  }
  return gdbstub::target_status::unsupported;
}

gdbstub::target_status mem_component::write_mem(uint64_t, std::span<const std::byte>) {
  return gdbstub::target_status::unsupported;
}

} // namespace w1replay::gdb
