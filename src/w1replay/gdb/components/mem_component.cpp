#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/memory_merge.hpp"

namespace w1replay::gdb {

namespace {
bool has_any_known_byte(
    const std::vector<std::optional<uint8_t>>& recorded, const std::vector<std::byte>& module_bytes,
    std::span<const uint8_t> module_known, size_t size
) {
  for (size_t i = 0; i < size && i < recorded.size(); ++i) {
    if (recorded[i].has_value()) {
      return true;
    }
  }
  if (module_bytes.size() < size || module_known.size() < size) {
    return false;
  }
  for (size_t i = 0; i < size; ++i) {
    if (module_known[i]) {
      return true;
    }
  }
  return false;
}
} // namespace

mem_component::mem_component(adapter_state& state) : state_(state) {}

gdbstub::target_status mem_component::read_mem(uint64_t addr, std::span<std::byte> out) {
  if (!state_.session) {
    return gdbstub::target_status::unsupported;
  }

  std::vector<std::optional<uint8_t>> recorded;
  recorded.resize(out.size());
  if (state_.track_memory) {
    recorded = state_.session->read_memory(addr, out.size());
    if (recorded.size() != out.size()) {
      return gdbstub::target_status::fault;
    }
  }

  auto module_read = state_.module_source_state.read_address_image(state_.context, addr, out.size());

  bool complete = merge_memory_bytes(recorded, module_read.bytes, module_read.known, out);
  const bool any_known = has_any_known_byte(recorded, module_read.bytes, module_read.known, out.size());
  if (complete || any_known) {
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
