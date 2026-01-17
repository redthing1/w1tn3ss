#include "replay_state_applier.hpp"

namespace w1::rewind {

bool replay_state_applier::apply_record(
    const trace_record& record,
    uint64_t active_thread_id,
    bool track_registers,
    bool track_memory,
    replay_state& state
) const {
  if (!(track_registers || track_memory) || active_thread_id == 0) {
    return true;
  }

  if (std::holds_alternative<register_delta_record>(record)) {
    return apply_register_deltas(
        std::get<register_delta_record>(record),
        active_thread_id,
        track_registers,
        state
    );
  }
  if (std::holds_alternative<memory_access_record>(record)) {
    return apply_memory_access(
        std::get<memory_access_record>(record),
        active_thread_id,
        track_memory,
        state
    );
  }
  if (std::holds_alternative<boundary_record>(record)) {
    return apply_boundary(
        std::get<boundary_record>(record),
        active_thread_id,
        track_registers,
        track_memory,
        state
    );
  }

  return true;
}

bool replay_state_applier::apply_register_deltas(
    const register_delta_record& record,
    uint64_t active_thread_id,
    bool track_registers,
    replay_state& state
) const {
  if (!track_registers) {
    return true;
  }
  if (record.thread_id != active_thread_id) {
    return true;
  }
  state.apply_register_deltas(record.deltas);
  return true;
}

bool replay_state_applier::apply_memory_access(
    const memory_access_record& record,
    uint64_t active_thread_id,
    bool track_memory,
    replay_state& state
) const {
  if (!track_memory) {
    return true;
  }
  if (record.thread_id != active_thread_id) {
    return true;
  }
  if (!record.value_known || record.data.empty()) {
    return true;
  }
  if (record.kind != memory_access_kind::write) {
    return true;
  }
  state.apply_memory_bytes(record.address, record.data);
  return true;
}

bool replay_state_applier::apply_boundary(
    const boundary_record& record,
    uint64_t active_thread_id,
    bool track_registers,
    bool track_memory,
    replay_state& state
) const {
  if (record.thread_id != active_thread_id) {
    return true;
  }

  if (track_registers) {
    state.apply_register_snapshot(record.registers);
  }

  if (!track_memory || record.stack_window.empty()) {
    return true;
  }

  uint64_t sp = 0;
  bool have_sp = false;
  if (context_.sp_reg_id.has_value()) {
    if (track_registers) {
      auto value = state.register_value(*context_.sp_reg_id);
      if (value.has_value()) {
        sp = *value;
        have_sp = true;
      }
    }
    if (!have_sp) {
      for (const auto& reg : record.registers) {
        if (reg.reg_id == *context_.sp_reg_id) {
          sp = reg.value;
          have_sp = true;
          break;
        }
      }
    }
  }

  if (have_sp) {
    state.apply_stack_window(sp, record.stack_window);
  }

  return true;
}

} // namespace w1::rewind
