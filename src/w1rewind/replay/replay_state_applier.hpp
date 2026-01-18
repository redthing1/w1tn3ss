#pragma once

#include <cstdint>

#include "replay_context.hpp"
#include "replay_state.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

class replay_state_applier {
public:
  explicit replay_state_applier(const replay_context& context) : context_(context) {}

  bool apply_record(
      const trace_record& record,
      uint64_t active_thread_id,
      bool track_registers,
      bool track_memory,
      replay_state& state
  ) const;

  bool apply_snapshot(
      const snapshot_record& record,
      uint64_t active_thread_id,
      bool track_registers,
      bool track_memory,
      replay_state& state
  ) const;

  bool apply_register_deltas(
      const register_delta_record& record,
      uint64_t active_thread_id,
      bool track_registers,
      replay_state& state
  ) const;

  bool apply_memory_access(
      const memory_access_record& record,
      uint64_t active_thread_id,
      bool track_memory,
      replay_state& state
  ) const;

private:
  const replay_context& context_;
};

} // namespace w1::rewind
