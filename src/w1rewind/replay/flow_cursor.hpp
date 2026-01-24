#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "flow_extractor.hpp"
#include "flow_types.hpp"
#include "history_window.hpp"
#include "record_stream_cursor.hpp"
#include "w1rewind/trace/trace_index.hpp"

namespace w1::rewind {

enum class flow_error_kind { none, begin_of_trace, end_of_trace, other };

class flow_cursor {
public:
  flow_cursor(
      record_stream_cursor stream, flow_extractor extractor, history_window history, std::shared_ptr<trace_index> index
  );

  void set_observer(flow_record_observer* observer);
  void set_history_enabled(bool enabled);
  void set_history_size(uint32_t size);
  void set_cancel_checker(std::function<bool()> checker);

  bool open();
  void close();

  bool seek(uint64_t thread_id, uint64_t sequence);
  bool seek_from_location(uint64_t thread_id, uint64_t sequence, const trace_record_location& location);

  bool step_forward(flow_step& out, trace_record_location* location = nullptr);
  bool step_backward(flow_step& out);

  const replay_context& context() const { return *extractor_.context(); }
  bool has_position() const { return has_position_; }
  const flow_step& current_step() const { return current_step_; }
  std::string_view error() const { return error_; }
  flow_error_kind error_kind() const { return error_kind_; }

private:
  struct buffered_flow {
    flow_step step;
    trace_record_location location;
  };

  void clear_error();
  void set_error(flow_error_kind kind, const std::string& message);
  bool check_cancel();
  void reset_position_state();
  void clear_buffered_flow();
  bool uses_history_only() const;
  bool ensure_stream_synced();
  bool scan_until_sequence(uint64_t thread_id, uint64_t sequence);
  bool read_next_flow(flow_step& out, trace_record_location* location);
  bool consume_sequence_records(uint64_t thread_id, uint64_t sequence);
  bool seek_to_history(size_t index);
  uint64_t window_start_sequence(uint64_t target) const;
  bool prefill_history_window(uint64_t target, flow_step& out);

  record_stream_cursor stream_;
  flow_extractor extractor_;
  history_window history_;
  std::shared_ptr<trace_index> index_;
  uint32_t history_size_ = 1024;
  uint64_t active_thread_id_ = 0;
  flow_step current_step_{};
  std::optional<buffered_flow> buffered_flow_{};
  bool has_position_ = false;
  bool open_ = false;
  bool history_enabled_ = true;
  flow_record_observer* observer_ = nullptr;
  std::function<bool()> cancel_checker_{};
  bool stream_desynced_ = false;
  std::string error_;
  flow_error_kind error_kind_ = flow_error_kind::none;
};

} // namespace w1::rewind
