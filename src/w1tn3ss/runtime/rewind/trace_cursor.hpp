#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "trace_index.hpp"
#include "trace_reader.hpp"

namespace w1::rewind {

struct trace_cursor_config {
  std::string trace_path;
  std::string index_path;
};

class trace_cursor {
public:
  explicit trace_cursor(trace_cursor_config config);

  bool open();
  void close();

  bool load_index();
  bool seek_flow(uint64_t thread_id, uint64_t sequence);
  bool seek_to_location(const trace_record_location& location);

  bool read_next(trace_record& record);
  bool read_next(trace_record& record, trace_record_location* location);

  const trace_reader& reader() const { return reader_; }
  const trace_index* index() const { return index_ ? &(*index_) : nullptr; }
  const std::string& error() const { return error_; }

private:
  bool seek_to_anchor(const trace_anchor& anchor);
  bool scan_to_flow(uint64_t thread_id, uint64_t sequence);

  trace_cursor_config config_;
  trace_reader reader_;
  std::optional<trace_index> index_;
  std::optional<trace_record> pending_;
  std::optional<trace_record_location> pending_location_;
  bool open_ = false;
  std::string error_;
};

} // namespace w1::rewind
