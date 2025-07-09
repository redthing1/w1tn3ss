#include "jsonl_writer.hpp"

#include <algorithm>
#include <cstring>

namespace w1::util {

jsonl_writer::jsonl_writer(const std::string& path)
    : buffer_size_(DEFAULT_BUFFER_SIZE), flush_event_count_(DEFAULT_FLUSH_EVENT_COUNT) {
  buffer_.reserve(buffer_size_);
  
  if (!path.empty()) {
    open(path);
  }
}

jsonl_writer::~jsonl_writer() {
  close();
}

bool jsonl_writer::open(const std::string& path) {
  std::lock_guard<std::mutex> lock(write_mutex_);
  
  // close existing file if open
  if (file_.is_open()) {
    flush_internal();
    file_.close();
  }
  
  // reset state
  buffer_pos_ = 0;
  event_count_ = 0;
  flush_count_ = 0;
  bytes_written_ = 0;
  
  // open new file
  file_.open(path, std::ios::out | std::ios::binary);
  return file_.is_open();
}

bool jsonl_writer::write_line(const std::string& json) {
  // ensure json doesn't already have newline
  size_t len = json.length();
  bool needs_newline = (len == 0 || json[len - 1] != '\n');
  
  size_t required = len + (needs_newline ? 1 : 0);
  
  std::lock_guard<std::mutex> lock(write_mutex_);
  
  if (!file_.is_open()) {
    return false;
  }
  
  ensure_capacity(required);
  
  // copy json to buffer
  std::memcpy(buffer_.data() + buffer_pos_, json.data(), len);
  buffer_pos_ += len;
  
  // add newline if needed
  if (needs_newline) {
    buffer_[buffer_pos_++] = '\n';
  }
  
  event_count_++;
  
  // check if we should flush based on event count
  if (event_count_ % flush_event_count_ == 0) {
    flush_internal();
  }
  
  return true;
}

bool jsonl_writer::write_raw(const char* data, size_t len) {
  std::lock_guard<std::mutex> lock(write_mutex_);
  
  if (!file_.is_open() || !data || len == 0) {
    return false;
  }
  
  ensure_capacity(len);
  
  std::memcpy(buffer_.data() + buffer_pos_, data, len);
  buffer_pos_ += len;
  
  // count newlines as events
  size_t newline_count = std::count(data, data + len, '\n');
  event_count_ += newline_count;
  
  // check if we should flush
  if (newline_count > 0 && event_count_ % flush_event_count_ < newline_count) {
    flush_internal();
  }
  
  return true;
}

void jsonl_writer::flush() {
  std::lock_guard<std::mutex> lock(write_mutex_);
  flush_internal();
}

void jsonl_writer::close() {
  std::lock_guard<std::mutex> lock(write_mutex_);
  
  if (file_.is_open()) {
    flush_internal();
    file_.close();
  }
}

void jsonl_writer::ensure_capacity(size_t required) {
  // if adding required bytes would exceed buffer, flush first
  if (buffer_pos_ + required > buffer_size_) {
    flush_internal();
  }
  
  // if single item is larger than entire buffer, write directly
  if (required > buffer_size_) {
    if (buffer_pos_ > 0) {
      flush_internal();
    }
    // this item will be written directly in the next flush
  }
}

void jsonl_writer::flush_internal() {
  if (!file_.is_open() || buffer_pos_ == 0) {
    return;
  }
  
  file_.write(buffer_.data(), buffer_pos_);
  file_.flush();
  
  bytes_written_ += buffer_pos_;
  buffer_pos_ = 0;
  flush_count_++;
}

} // namespace w1::util