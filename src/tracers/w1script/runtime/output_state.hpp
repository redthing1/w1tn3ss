#pragma once

#include "w1formats/jsonl_writer.hpp"

#include <memory>
#include <string>

#include <redlog.hpp>

namespace w1::tracers::script::runtime {

class output_state {
public:
  output_state();

  bool open(const std::string& filename, const std::string& metadata_json);
  bool write_event(const std::string& json_line);
  void close();

  bool is_open() const { return initialized_ && writer_ && writer_->is_open(); }
  size_t event_count() const { return event_count_; }

private:
  std::unique_ptr<w1::io::jsonl_writer> writer_;
  size_t event_count_ = 0;
  bool initialized_ = false;
  redlog::logger logger_;

  std::string build_summary_json() const;
};

} // namespace w1::tracers::script::runtime
