#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "flow_cursor.hpp"
#include "w1rewind/trace/replay_checkpoint.hpp"
#include "w1rewind/trace/record_stream.hpp"
#include "replay_context.hpp"
#include "block_decoder.hpp"
#include "replay_instruction_cursor.hpp"
#include "replay_position.hpp"
#include "replay_state.hpp"
#include "replay_state_applier.hpp"
#include "stateful_flow_cursor.hpp"
#include "mapping_state.hpp"

namespace w1::rewind {

struct replay_session_config {
  std::shared_ptr<trace_record_stream> stream;
  std::shared_ptr<trace_index> index;
  std::shared_ptr<replay_checkpoint_index> checkpoint;
  replay_context context;
  uint32_t history_size = 1024;
  bool track_registers = false;
  bool track_memory = false;
  bool track_mappings = false;
  bool strict_instructions = false;
  uint64_t thread_id = 0;
  uint64_t start_sequence = 0;
  block_decoder* block_decoder = nullptr;
};

class replay_session {
public:
  explicit replay_session(replay_session_config config);

  bool open();
  void close();

  bool select_thread(uint64_t thread_id, uint64_t sequence);
  bool step_flow();
  bool step_backward();
  bool step_instruction();
  bool step_instruction_backward();
  bool sync_instruction_position(bool forward = true);

  const flow_step& current_step() const { return current_step_; }
  const replay_context& context() const { return context_; }
  const std::vector<std::string>& register_names() const { return context_.default_register_names; }
  const std::vector<register_spec>& register_specs() const { return context_.default_registers; }
  std::vector<std::optional<uint64_t>> read_registers() const;
  bool read_register_bytes(uint32_t reg_id, std::span<std::byte> out, bool& known) const;
  memory_read read_memory(uint64_t address, size_t size) const;
  const file_header& header() const { return context_.header; }
  const std::vector<image_record>& images() const { return context_.images; }
  const std::vector<replay_thread_info>& threads() const { return context_.threads; }
  const replay_state* state() const;
  const mapping_state* mappings() const;
  std::optional<replay_notice> take_notice();
  const std::string& error() const { return error_; }
  enum class replay_error_kind { none, begin_of_trace, end_of_trace, other };
  replay_error_kind error_kind() const { return error_kind_; }
  const replay_position& current_position() const { return current_position_; }

private:
  bool apply_checkpoint(const replay_checkpoint_entry& checkpoint);
  bool validate_checkpoint(const replay_checkpoint_index& index);
  const replay_checkpoint_entry* find_checkpoint(uint64_t thread_id, uint64_t sequence) const;
  bool step_flow_backward_internal(flow_step& out);
  bool step_flow_internal(flow_step& out);
  void reset_instruction_cursor();
  void clear_error();
  void set_error(const std::string& message);
  void set_error(replay_error_kind kind, const std::string& message);

  replay_session_config config_;
  replay_context context_{};
  std::optional<flow_cursor> flow_cursor_;
  std::optional<stateful_flow_cursor> stateful_flow_cursor_;
  std::optional<replay_state_applier> state_applier_;
  replay_state state_{};
  std::optional<mapping_state> mapping_state_;
  std::optional<replay_instruction_cursor> instruction_cursor_;
  std::optional<replay_notice> notice_;
  replay_position current_position_{};
  flow_step current_step_{};
  uint64_t active_thread_id_ = 0;
  block_decoder* block_decoder_ = nullptr;
  std::shared_ptr<replay_checkpoint_index> checkpoint_index_;
  bool open_ = false;
  bool has_position_ = false;
  std::string error_;
  replay_error_kind error_kind_ = replay_error_kind::none;
};

} // namespace w1::rewind
