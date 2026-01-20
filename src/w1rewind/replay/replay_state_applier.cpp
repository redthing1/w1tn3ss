#include "replay_state_applier.hpp"

namespace w1::rewind {

bool replay_state_applier::apply_record(
    const trace_record& record, uint64_t active_thread_id, bool track_registers, bool track_memory, replay_state& state
) const {
  if (!(track_registers || track_memory) || active_thread_id == 0) {
    return true;
  }

  if (std::holds_alternative<register_delta_record>(record)) {
    return apply_register_deltas(std::get<register_delta_record>(record), active_thread_id, track_registers, state);
  }
  if (std::holds_alternative<register_bytes_record>(record)) {
    return apply_register_bytes(std::get<register_bytes_record>(record), active_thread_id, track_registers, state);
  }
  if (std::holds_alternative<memory_access_record>(record)) {
    return apply_memory_access(std::get<memory_access_record>(record), active_thread_id, track_memory, state);
  }
  if (std::holds_alternative<snapshot_record>(record)) {
    return apply_snapshot(std::get<snapshot_record>(record), active_thread_id, track_registers, track_memory, state);
  }

  return true;
}

bool replay_state_applier::apply_register_deltas(
    const register_delta_record& record, uint64_t active_thread_id, bool track_registers, replay_state& state
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

bool replay_state_applier::apply_register_bytes(
    const register_bytes_record& record, uint64_t active_thread_id, bool track_registers, replay_state& state
) const {
  if (!track_registers) {
    return true;
  }
  if (record.thread_id != active_thread_id) {
    return true;
  }
  return state.apply_register_bytes(record.entries, record.data);
}

bool replay_state_applier::apply_memory_access(
    const memory_access_record& record, uint64_t active_thread_id, bool track_memory, replay_state& state
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

bool replay_state_applier::apply_snapshot(
    const snapshot_record& record, uint64_t active_thread_id, bool track_registers, bool track_memory,
    replay_state& state
) const {
  if (record.thread_id != active_thread_id) {
    return true;
  }

  if (track_registers && !record.registers.empty()) {
    state.apply_register_snapshot(record.registers);
  }

  if (!track_memory || record.stack_segments.empty()) {
    return true;
  }

  state.apply_stack_segments(record.stack_segments);

  return true;
}

} // namespace w1::rewind
