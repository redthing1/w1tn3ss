#include "w1tn3ss/io/jsonl_writer.hpp"

#include <algorithm>
#include <cstring>

namespace w1::io {
namespace {

size_t sanitize_buffer_size(size_t size) {
  if (size == 0) {
    return 1;
  }
  return size;
}

} // namespace

jsonl_writer::jsonl_writer()
    : config_(), buffer_size_bytes_(sanitize_buffer_size(config_.buffer_size_bytes)) {
  buffer_.resize(buffer_size_bytes_);
  reset_state();
}

jsonl_writer::jsonl_writer(const std::string& path, jsonl_writer_config config)
    : config_(config), buffer_size_bytes_(sanitize_buffer_size(config.buffer_size_bytes)) {
  buffer_.resize(buffer_size_bytes_);
  reset_state();

  if (!path.empty()) {
    open(path);
  }
}

jsonl_writer::~jsonl_writer() { close(); }

bool jsonl_writer::open(const std::string& path) {
  std::lock_guard<std::mutex> lock(mutex_);

  close_locked();

  file_.open(path, std::ios::out | std::ios::binary | std::ios::trunc);
  if (!file_.is_open()) {
    return false;
  }

  reset_state();
  return true;
}

void jsonl_writer::close() {
  std::lock_guard<std::mutex> lock(mutex_);

  close_locked();
}

void jsonl_writer::close_locked() {
  if (!file_.is_open()) {
    return;
  }

  flush_internal();
  file_.close();
}

bool jsonl_writer::write_line(std::string_view json) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (!file_.is_open()) {
    return false;
  }

  if (!json.empty()) {
    if (!append_bytes(json.data(), json.size())) {
      return false;
    }
  }

  if (json.empty() || json.back() != '\n') {
    if (!append_bytes("\n", 1)) {
      return false;
    }
  }

  event_count_ += 1;
  return update_flush_thresholds();
}

bool jsonl_writer::write_raw(const char* data, size_t len) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (!file_.is_open() || !data || len == 0) {
    return false;
  }

  if (!append_bytes(data, len)) {
    return false;
  }

  size_t newline_count = static_cast<size_t>(std::count(data, data + len, '\n'));
  if (newline_count > 0) {
    event_count_ += newline_count;
  }

  return update_flush_thresholds();
}

void jsonl_writer::flush() {
  std::lock_guard<std::mutex> lock(mutex_);
  flush_internal();
}

bool jsonl_writer::append_bytes(const char* data, size_t len) {
  if (len == 0) {
    return true;
  }

  if (len > buffer_size_bytes_) {
    if (!flush_internal()) {
      return false;
    }

    file_.write(data, static_cast<std::streamsize>(len));
    if (!file_) {
      return false;
    }

    bytes_written_ += len;
    return flush_file();
  }

  if (buffer_pos_ + len > buffer_size_bytes_) {
    if (!flush_internal()) {
      return false;
    }
  }

  std::memcpy(buffer_.data() + buffer_pos_, data, len);
  buffer_pos_ += len;
  return true;
}

bool jsonl_writer::flush_internal() {
  if (!file_.is_open()) {
    return false;
  }

  if (buffer_pos_ == 0) {
    return true;
  }

  file_.write(buffer_.data(), static_cast<std::streamsize>(buffer_pos_));
  if (!file_) {
    return false;
  }

  bytes_written_ += buffer_pos_;
  buffer_pos_ = 0;

  return flush_file();
}

bool jsonl_writer::flush_file() {
  file_.flush();
  if (!file_) {
    return false;
  }

  flush_count_ += 1;
  return true;
}

void jsonl_writer::reset_state() {
  buffer_pos_ = 0;
  event_count_ = 0;
  flush_count_ = 0;
  bytes_written_ = 0;
  next_event_flush_ = config_.flush_event_count > 0 ? config_.flush_event_count : 0;
}

bool jsonl_writer::update_flush_thresholds() {
  bool should_flush = false;

  if (config_.flush_event_count > 0 && event_count_ >= next_event_flush_) {
    should_flush = true;
    while (event_count_ >= next_event_flush_) {
      next_event_flush_ += config_.flush_event_count;
    }
  }

  if (config_.flush_byte_count > 0 && buffer_pos_ >= config_.flush_byte_count) {
    should_flush = true;
  }

  if (should_flush) {
    return flush_internal();
  }

  return true;
}

} // namespace w1::io
