#include "adapter_components.hpp"

#include "memory_map.hpp"
#include "memory_merge.hpp"
#include "stepper.hpp"
#include "value_codec.hpp"

namespace w1replay::gdb {

regs_component::regs_component(adapter_state& state) : state_(state) {}

size_t regs_component::reg_size(int regno) const {
  if (regno < 0 || static_cast<size_t>(regno) >= state_.layout.registers.size()) {
    return 0;
  }
  return static_cast<size_t>(state_.layout.registers[static_cast<size_t>(regno)].bits / 8);
}

gdbstub::target_status regs_component::read_reg(int regno, std::span<std::byte> out) {
  if (regno < 0 || static_cast<size_t>(regno) >= state_.layout.registers.size()) {
    return gdbstub::target_status::invalid;
  }

  size_t size = reg_size(regno);
  if (size == 0 || out.size() < size) {
    return gdbstub::target_status::invalid;
  }

  auto fill_unknown = [&](std::span<std::byte> buffer) {
    std::fill(buffer.begin(), buffer.end(), std::byte{0xcc});
  };

  const auto& reg = state_.layout.registers[static_cast<size_t>(regno)];
  if (reg.is_pc) {
    auto pc = state_.current_pc();
    if (!pc.has_value()) {
      fill_unknown(out);
      return gdbstub::target_status::ok;
    }
    if (!encode_uint64(*pc, size, out, state_.target_endian)) {
      return gdbstub::target_status::invalid;
    }
    return gdbstub::target_status::ok;
  }

  if (!reg.trace_index.has_value()) {
    fill_unknown(out);
    return gdbstub::target_status::ok;
  }
  if (!state_.session) {
    fill_unknown(out);
    return gdbstub::target_status::ok;
  }

  if (reg.value_kind == w1::rewind::register_value_kind::bytes) {
    bool known = false;
    if (!state_.session->read_register_bytes(static_cast<uint16_t>(*reg.trace_index), out, known)) {
      return gdbstub::target_status::invalid;
    }
    if (!known) {
      fill_unknown(out);
    }
    return gdbstub::target_status::ok;
  }

  auto regs = state_.session->read_registers();
  if (*reg.trace_index >= regs.size()) {
    fill_unknown(out);
    return gdbstub::target_status::ok;
  }
  if (!regs[*reg.trace_index].has_value()) {
    fill_unknown(out);
    return gdbstub::target_status::ok;
  }
  if (!encode_uint64(*regs[*reg.trace_index], size, out, state_.target_endian)) {
    return gdbstub::target_status::invalid;
  }
  return gdbstub::target_status::ok;
}

gdbstub::target_status regs_component::write_reg(int, std::span<const std::byte>) {
  return gdbstub::target_status::unsupported;
}

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
  return complete ? gdbstub::target_status::ok : gdbstub::target_status::unsupported;
}

gdbstub::target_status mem_component::write_mem(uint64_t, std::span<const std::byte>) {
  return gdbstub::target_status::unsupported;
}

run_component::run_component(adapter_state& state) : state_(state) {}

gdbstub::run_capabilities run_component::capabilities() const {
  gdbstub::run_capabilities caps{};
  caps.reverse_step = true;
  caps.reverse_continue = true;
  return caps;
}

gdbstub::resume_result run_component::resume(const gdbstub::resume_request& request) {
  if (!state_.session) {
    gdbstub::resume_result result{};
    result.state = gdbstub::resume_result::state::exited;
    result.stop = gdbstub::stop_reason{gdbstub::stop_kind::exited, 0};
    result.exit_code = 0;
    return result;
  }

  run_policy policy = state_.make_run_policy();

  stepper_result result{};
  if (request.action == gdbstub::resume_action::step) {
    result = resume_step(*state_.session, policy, state_.breakpoints, state_.active_thread_id, request.direction);
  } else if (request.action == gdbstub::resume_action::cont) {
    result = resume_continue(*state_.session, policy, state_.breakpoints, state_.active_thread_id, request.direction);
  } else {
    result = resume_step(*state_.session, policy, state_.breakpoints, state_.active_thread_id, request.direction);
  }
  state_.last_stop = result.last_stop;
  return result.resume;
}

breakpoints_component::breakpoints_component(adapter_state& state) : state_(state) {}

gdbstub::target_status breakpoints_component::set_breakpoint(const gdbstub::breakpoint_spec& request) {
  if (request.type != gdbstub::breakpoint_type::software) {
    return gdbstub::target_status::unsupported;
  }
  state_.breakpoints.insert(request.addr);
  if (state_.session) {
    state_.session->add_breakpoint(request.addr);
  }
  return gdbstub::target_status::ok;
}

gdbstub::target_status breakpoints_component::remove_breakpoint(const gdbstub::breakpoint_spec& request) {
  if (request.type != gdbstub::breakpoint_type::software) {
    return gdbstub::target_status::unsupported;
  }
  state_.breakpoints.erase(request.addr);
  if (state_.session) {
    state_.session->remove_breakpoint(request.addr);
  }
  return gdbstub::target_status::ok;
}

threads_component::threads_component(adapter_state& state) : state_(state) {}

std::vector<uint64_t> threads_component::thread_ids() const { return {state_.active_thread_id}; }

uint64_t threads_component::current_thread() const { return state_.active_thread_id; }

gdbstub::target_status threads_component::set_current_thread(uint64_t) {
  return gdbstub::target_status::unsupported;
}

std::optional<uint64_t> threads_component::thread_pc(uint64_t tid) const {
  if (tid != state_.active_thread_id) {
    return std::nullopt;
  }
  return state_.current_pc();
}

std::optional<std::string> threads_component::thread_name(uint64_t tid) const {
  for (const auto& info : state_.context.threads) {
    if (info.thread_id == tid) {
      return info.name;
    }
  }
  return std::nullopt;
}

std::optional<gdbstub::stop_reason> threads_component::thread_stop_reason(uint64_t tid) const {
  if (tid != state_.active_thread_id) {
    return std::nullopt;
  }
  return state_.last_stop;
}

memory_layout_component::memory_layout_component(adapter_state& state) : state_(state) {}

std::vector<gdbstub::memory_region> memory_layout_component::memory_map() const {
  const auto* replay_state = (state_.session && state_.track_memory) ? state_.session->state() : nullptr;
  return build_memory_map(state_.context.modules, state_.context.memory_map, replay_state);
}

register_info_component::register_info_component(adapter_state& state) : state_(state) {}

std::optional<gdbstub::register_info> register_info_component::get_register_info(int regno) const {
  if (regno < 0 || static_cast<size_t>(regno) >= state_.layout.registers.size()) {
    return std::nullopt;
  }
  const auto& reg = state_.layout.registers[static_cast<size_t>(regno)];
  gdbstub::register_info info{};
  info.name = reg.name;
  info.bitsize = static_cast<int>(reg.bits);
  info.encoding = "uint";
  info.format = "hex";
  info.set = "general";
  if (reg.is_pc) {
    info.generic = "pc";
  } else if (reg.is_sp) {
    info.generic = "sp";
  }
  return info;
}

} // namespace w1replay::gdb
