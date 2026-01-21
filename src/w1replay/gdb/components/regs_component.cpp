#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/value_codec.hpp"

#include <algorithm>

namespace w1replay::gdb {

regs_component::regs_component(const adapter_services& services) : services_(services) {}

size_t regs_component::reg_size(int regno) const {
  if (!services_.layout) {
    return 0;
  }
  if (regno < 0 || static_cast<size_t>(regno) >= services_.layout->registers.size()) {
    return 0;
  }
  return static_cast<size_t>(services_.layout->registers[static_cast<size_t>(regno)].bits / 8);
}

gdbstub::target_status regs_component::read_reg(int regno, std::span<std::byte> out) {
  if (!services_.layout) {
    return gdbstub::target_status::invalid;
  }
  if (regno < 0 || static_cast<size_t>(regno) >= services_.layout->registers.size()) {
    return gdbstub::target_status::invalid;
  }

  size_t size = reg_size(regno);
  if (size == 0 || out.size() < size) {
    return gdbstub::target_status::invalid;
  }

  auto fill_unknown = [&](std::span<std::byte> buffer) { std::fill(buffer.begin(), buffer.end(), std::byte{0xcc}); };

  const auto& reg = services_.layout->registers[static_cast<size_t>(regno)];
  if (reg.is_pc) {
    if (!services_.session) {
      fill_unknown(out);
      return gdbstub::target_status::ok;
    }
    uint64_t pc = services_.session->current_step().address;
    if (!encode_uint64(pc, size, out, services_.target_endian)) {
      return gdbstub::target_status::invalid;
    }
    return gdbstub::target_status::ok;
  }

  if (!reg.trace_index.has_value()) {
    fill_unknown(out);
    return gdbstub::target_status::ok;
  }
  if (!services_.session) {
    fill_unknown(out);
    return gdbstub::target_status::ok;
  }

  if (reg.value_kind == w1::rewind::register_value_kind::bytes) {
    bool known = false;
    if (!services_.session->read_register_bytes(static_cast<uint16_t>(*reg.trace_index), out, known)) {
      return gdbstub::target_status::invalid;
    }
    if (!known) {
      fill_unknown(out);
    }
    return gdbstub::target_status::ok;
  }

  auto regs = services_.session->read_registers();
  if (*reg.trace_index >= regs.size()) {
    fill_unknown(out);
    return gdbstub::target_status::ok;
  }
  if (!regs[*reg.trace_index].has_value()) {
    fill_unknown(out);
    return gdbstub::target_status::ok;
  }
  if (!encode_uint64(*regs[*reg.trace_index], size, out, services_.target_endian)) {
    return gdbstub::target_status::invalid;
  }
  return gdbstub::target_status::ok;
}

gdbstub::target_status regs_component::write_reg(int, std::span<const std::byte>) {
  return gdbstub::target_status::unsupported;
}

} // namespace w1replay::gdb
