#pragma once

#include <cstdint>
#include <memory>
#include <deque>
#include <optional>
#include <string>
#include <string_view>

#include "replay_context.hpp"
#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/trace/record_stream.hpp"
#include "w1rewind/trace/trace_index.hpp"

namespace w1::rewind {

struct flow_step {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  uint32_t size = 0;
  uint64_t address = 0;
  uint64_t block_id = 0;
  uint32_t flags = 0;
  bool is_block = false;
};

enum class flow_error_kind { none, begin_of_trace, end_of_trace, other };

class flow_record_observer {
public:
  virtual ~flow_record_observer() = default;
  virtual bool on_record(const trace_record& record, uint64_t active_thread_id, std::string& error) = 0;
};

struct flow_cursor_config {
  std::shared_ptr<trace_record_stream> stream;
  std::shared_ptr<trace_index> index;
  uint32_t history_size = 1024;
  const replay_context* context = nullptr;
};

class flow_cursor {
public:
  explicit flow_cursor(flow_cursor_config config);

  void set_observer(flow_record_observer* observer);
  void set_history_enabled(bool enabled);
  void set_history_size(uint32_t size);

  bool open();
  void close();

  bool seek(uint64_t thread_id, uint64_t sequence);
  bool seek_from_location(uint64_t thread_id, uint64_t sequence, const trace_record_location& location);

  bool step_forward(flow_step& out, trace_record_location* location = nullptr);
  bool step_backward(flow_step& out);

  const replay_context& context() const { return *context_; }
  bool has_position() const { return has_position_; }
  const flow_step& current_step() const { return current_step_; }
  std::string_view error() const { return error_; }
  flow_error_kind error_kind() const { return error_kind_; }

private:
  enum class flow_kind { instructions, blocks };

  struct history_entry {
    flow_step step;
    trace_record_location location;
  };

  void clear_error();
  void set_error(flow_error_kind kind, const std::string& message);
  bool scan_until_sequence(uint64_t thread_id, uint64_t sequence);
  bool try_parse_flow(const trace_record& record, flow_step& out, bool& is_flow);
  bool read_next_flow(flow_step& out, trace_record_location* location);
  bool consume_sequence_records(uint64_t thread_id, uint64_t sequence);
  void push_history(const flow_step& step, const trace_record_location& location);
  bool seek_to_history(size_t index);
  bool handle_non_flow(const trace_record& record);
  uint64_t window_start_sequence(uint64_t target) const;
  bool prefill_history_window(uint64_t target, flow_step& out);

  flow_cursor_config config_;
  std::shared_ptr<trace_record_stream> stream_;
  std::shared_ptr<trace_index> index_;
  const replay_context* context_ = nullptr;
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
  bool history_enabled_ = true;
  flow_record_observer* observer_ = nullptr;
  std::string error_;
  flow_error_kind error_kind_ = flow_error_kind::none;
};

} // namespace w1::rewind
