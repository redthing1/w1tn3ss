#include "record_stream_cursor.hpp"

namespace w1::rewind {

record_stream_cursor::record_stream_cursor(std::shared_ptr<trace_record_stream> stream) : stream_(std::move(stream)) {}

bool record_stream_cursor::open(std::string& error) {
  if (!stream_) {
    error = "trace stream missing";
    return false;
  }
  if (!stream_->open()) {
    error = std::string(stream_->error());
    return false;
  }
  open_ = true;
  return true;
}

void record_stream_cursor::close() {
  if (stream_) {
    stream_->close();
  }
  open_ = false;
}

bool record_stream_cursor::seek(const trace_record_location& location, std::string& error) {
  if (!stream_) {
    error = "trace stream missing";
    return false;
  }
  if (!stream_->seek_to_location(location)) {
    error = std::string(stream_->error());
    return false;
  }
  return true;
}

bool record_stream_cursor::read_next(trace_record& out, trace_record_location& location, std::string& error) {
  if (!stream_) {
    error = "trace stream missing";
    return false;
  }
  if (!stream_->read_next(out, &location)) {
    if (!stream_->error().empty()) {
      error = std::string(stream_->error());
    }
    return false;
  }
  return true;
}

const file_header& record_stream_cursor::header() const { return stream_->header(); }

} // namespace w1::rewind
