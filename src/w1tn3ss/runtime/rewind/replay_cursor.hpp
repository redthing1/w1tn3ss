#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "trace_cursor.hpp"
#include "trace_format.hpp"
#include "replay_state.hpp"

namespace w1::rewind {

struct replay_cursor_config {
  std::string trace_path;
  std::string index_path;
  uint32_t history_size = 1024;
  bool track_registers = false;
  bool track_memory = false;
};

struct flow_step {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  uint64_t module_id = 0;
  uint64_t module_offset = 0;
  uint32_t size = 0;
  uint64_t address = 0;
  bool is_block = false;
};

class replay_cursor {
public:
  explicit replay_cursor(replay_cursor_config config);

  bool open();
  void close();

  bool seek(uint64_t thread_id, uint64_t sequence);
  bool step_forward(flow_step& out);
  bool step_backward(flow_step& out);

  const std::vector<std::string>& register_names() const { return register_names_; }
  const replay_state* state() const { return track_registers_ || track_memory_ ? &state_ : nullptr; }
  const std::string& error() const { return error_; }

private:
  enum class flow_kind { instructions, blocks };

  struct history_entry {
    flow_step step;
    trace_record_location location;
  };

  bool load_metadata();
  bool scan_until_sequence(uint64_t thread_id, uint64_t sequence);
  bool resolve_address(uint64_t module_id, uint64_t module_offset, uint64_t& address);
  bool try_parse_flow(const trace_record& record, flow_step& out, bool& is_flow);
  bool apply_state_record(const trace_record& record);
  bool apply_boundary_record(const boundary_record& record);
  bool apply_register_deltas(const register_delta_record& record);
  bool apply_memory_access(const memory_access_record& record);
  std::optional<uint64_t> read_register_value(const std::vector<register_delta>& regs, uint16_t reg_id) const;
  bool read_next_flow(flow_step& out, trace_record_location* location);
  bool consume_sequence_records(uint64_t thread_id, uint64_t sequence);
  void push_history(const flow_step& step, const trace_record_location& location);
  bool seek_to_history(size_t index);

  replay_cursor_config config_;
  trace_cursor cursor_;
  std::unordered_map<uint64_t, module_record> modules_by_id_;
  std::unordered_map<uint64_t, block_definition_record> blocks_by_id_;
  std::vector<std::string> register_names_;
  std::optional<uint16_t> sp_reg_id_;
  replay_state state_{};
  std::deque<history_entry> history_;
  size_t history_pos_ = 0;
  uint32_t history_size_ = 1024;
  flow_kind flow_kind_ = flow_kind::instructions;
  uint64_t active_thread_id_ = 0;
  flow_step current_step_{};
  std::optional<flow_step> pending_flow_{};
  std::optional<trace_record_location> pending_location_{};
  bool has_position_ = false;
  bool open_ = false;
  bool track_registers_ = false;
  bool track_memory_ = false;
  std::string error_;
};

} // namespace w1::rewind
