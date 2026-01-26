#include "replay_state_applier.hpp"

namespace w1::rewind {

bool replay_state_applier::apply_record(
    const trace_record& record, uint64_t active_thread_id, bool track_registers, bool track_memory, replay_state& state,
    std::string& error
) const {
  error.clear();
  if (!(track_registers || track_memory) || active_thread_id == 0) {
    return true;
  }

  if (std::holds_alternative<reg_write_record>(record)) {
    return apply_reg_write(std::get<reg_write_record>(record), active_thread_id, track_registers, state, error);
  }
  if (std::holds_alternative<mem_access_record>(record)) {
    return apply_memory_access(std::get<mem_access_record>(record), active_thread_id, track_memory, state);
  }
  if (std::holds_alternative<snapshot_record>(record)) {
    return apply_snapshot(
        std::get<snapshot_record>(record), active_thread_id, track_registers, track_memory, state, error
    );
  }

  return true;
}

bool replay_state_applier::apply_reg_write(
    const reg_write_record& record, uint64_t active_thread_id, bool track_registers, replay_state& state,
    std::string& error
) const {
  error.clear();
  if (!track_registers) {
    return true;
  }
  if (record.thread_id != active_thread_id) {
    return true;
  }
  return state.apply_reg_write(record.regfile_id, record.entries, error);
}

bool replay_state_applier::apply_memory_access(
    const mem_access_record& record, uint64_t active_thread_id, bool track_memory, replay_state& state
) const {
  if (!track_memory) {
    return true;
  }
  if (record.thread_id != active_thread_id) {
    return true;
  }
  if ((record.flags & mem_access_value_known) == 0 || record.value.empty()) {
    return true;
  }
  state.apply_memory_bytes(record.space_id, record.address, record.value);
  return true;
}

bool replay_state_applier::apply_snapshot(
    const snapshot_record& record, uint64_t active_thread_id, bool track_registers, bool track_memory,
    replay_state& state, std::string& error
) const {
  error.clear();
  if (record.thread_id != active_thread_id) {
    return true;
  }

  if (track_registers && !record.registers.empty()) {
    if (!state.apply_register_snapshot(record.regfile_id, record.registers, error)) {
      return false;
    }
  }

  if (!track_memory || record.memory_segments.empty()) {
    return true;
  }

  state.apply_memory_segments(record.memory_segments);

  return true;
}

} // namespace w1::rewind
