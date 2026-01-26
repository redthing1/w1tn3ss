#pragma once

#include <memory>
#include <string>

#include "w1rewind/trace/record_stream.hpp"

namespace w1::rewind {

class record_stream_cursor {
public:
  explicit record_stream_cursor(std::shared_ptr<trace_record_stream> stream);

  bool open(std::string& error);
  void close();

  bool seek(const trace_record_location& location, std::string& error);
  bool read_next(trace_record& out, trace_record_location& location, std::string& error);

  const file_header& header() const;
  bool is_open() const { return open_; }

private:
  std::shared_ptr<trace_record_stream> stream_;
  bool open_ = false;
};

} // namespace w1::rewind
