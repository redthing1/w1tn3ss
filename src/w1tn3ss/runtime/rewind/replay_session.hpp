#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "replay_checkpoint.hpp"
#include "replay_context.hpp"
#include "replay_decode.hpp"
#include "replay_flow_cursor.hpp"
#include "replay_instruction_cursor.hpp"

namespace w1::rewind {

struct replay_session_config {
  std::string trace_path;
  std::string index_path;
  uint64_t thread_id = 0;
  uint64_t start_sequence = 0;
  uint32_t history_size = 1024;
  bool track_registers = true;
  bool track_memory = true;
  std::function<void(replay_context&)> context_hook;
  bool auto_build_index = true;
  std::string checkpoint_path;
  bool auto_build_checkpoint = false;
  uint32_t checkpoint_stride = 50000;
  bool checkpoint_include_memory = false;
  replay_block_decoder* block_decoder = nullptr;
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
  bool continue_until_break();

  void add_breakpoint(uint64_t address);
  void remove_breakpoint(uint64_t address);
  void clear_breakpoints();

  const flow_step& current_step() const { return current_step_; }
  const std::vector<std::string>& register_names() const { return context_.register_names; }
  std::vector<std::optional<uint64_t>> read_registers() const;
  std::vector<std::optional<uint8_t>> read_memory(uint64_t address, size_t size) const;
  const trace_header& header() const { return context_.header; }
  const std::vector<module_record>& modules() const { return context_.modules; }
  const std::vector<replay_thread_info>& threads() const { return context_.threads; }
  const replay_state* state() const;
  std::optional<replay_notice> take_notice();
  const std::string& error() const { return error_; }
  enum class replay_error_kind { none, begin_of_trace, end_of_trace, other };
  replay_error_kind error_kind() const { return error_kind_; }

private:
  bool ensure_index();
  bool load_context();
  bool ensure_flow_cursor();
  bool ensure_checkpoint();
  bool validate_checkpoint(const replay_checkpoint_index& index);
  const replay_checkpoint_entry* find_checkpoint(uint64_t thread_id, uint64_t sequence) const;
  bool step_flow_backward_internal(flow_step& out);
  bool step_flow_internal(flow_step& out);
  void reset_instruction_cursor();
  bool is_breakpoint_hit() const;
  void clear_error();
  void set_error(const std::string& message);
  void set_error(replay_error_kind kind, const std::string& message);

  replay_session_config config_;
  replay_context context_{};
  std::optional<replay_flow_cursor> flow_cursor_;
  std::optional<replay_instruction_cursor> instruction_cursor_;
  std::optional<replay_notice> notice_;
  std::unordered_set<uint64_t> breakpoints_;
  flow_step current_step_{};
  uint64_t active_thread_id_ = 0;
  std::string resolved_index_path_;
  replay_block_decoder* block_decoder_ = nullptr;
  std::optional<replay_checkpoint_index> checkpoint_index_;
  std::string resolved_checkpoint_path_;
  bool open_ = false;
  bool has_position_ = false;
  std::string error_;
  replay_error_kind error_kind_ = replay_error_kind::none;
};

} // namespace w1::rewind
