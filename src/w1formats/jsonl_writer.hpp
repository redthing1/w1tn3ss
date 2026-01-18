#pragma once

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace w1::io {

struct jsonl_writer_config {
  size_t buffer_size_bytes = 4 * 1024 * 1024;
  size_t flush_event_count = 1'000'000;
  size_t flush_byte_count = 0;
};

class jsonl_writer {
public:
  jsonl_writer();
  explicit jsonl_writer(const std::string& path, jsonl_writer_config config = {});
  ~jsonl_writer();

  jsonl_writer(const jsonl_writer&) = delete;
  jsonl_writer& operator=(const jsonl_writer&) = delete;
  jsonl_writer(jsonl_writer&&) = delete;
  jsonl_writer& operator=(jsonl_writer&&) = delete;

  bool open(const std::string& path);
  void close();
  bool is_open() const { return file_.is_open(); }

  bool write_line(std::string_view json);
  bool write_raw(const char* data, size_t len);

  void flush();

  size_t event_count() const { return event_count_; }
  size_t flush_count() const { return flush_count_; }
  size_t bytes_written() const { return bytes_written_; }
  size_t buffered_bytes() const { return buffer_pos_; }

private:
  bool append_bytes(const char* data, size_t len);
  bool flush_internal();
  bool flush_file();
  void reset_state();
  bool update_flush_thresholds();
  void close_locked();

  std::ofstream file_{};
  jsonl_writer_config config_{};
  std::vector<char> buffer_{};
  size_t buffer_size_bytes_ = 0;
  size_t buffer_pos_ = 0;
  size_t next_event_flush_ = 0;

  size_t event_count_ = 0;
  size_t flush_count_ = 0;
  size_t bytes_written_ = 0;

  mutable std::mutex mutex_{};
};

} // namespace w1::io
