#pragma once

#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace w1::util {

// elegant jsonl writer with automatic event-based flushing
// designed for high-performance streaming of json lines format
class jsonl_writer {
public:
  // sensible defaults: 64KB buffer, flush every 1000 events
  static constexpr size_t DEFAULT_BUFFER_SIZE = 64 * 1024;
  static constexpr size_t DEFAULT_FLUSH_EVENT_COUNT = 1000;

  // constructor opens file immediately if path is provided
  explicit jsonl_writer(const std::string& path = "");
  ~jsonl_writer();

  // open a file for writing (closes any existing file)
  bool open(const std::string& path);

  // check if writer is ready to accept data
  bool is_open() const { return file_.is_open(); }

  // write a json string as a complete line
  // returns false if write failed (e.g., file not open)
  bool write_line(const std::string& json);

  // write raw data (caller ensures it ends with newline)
  bool write_raw(const char* data, size_t len);

  // force flush of buffered data to disk
  void flush();

  // close file and flush any remaining data
  void close();

  // get current statistics
  size_t get_event_count() const { return event_count_; }
  size_t get_flush_count() const { return flush_count_; }
  size_t get_bytes_written() const { return bytes_written_; }

private:
  // internal buffer management
  void ensure_capacity(size_t required);
  void flush_internal();

  // file handle
  std::ofstream file_;
  std::mutex write_mutex_;

  // buffering
  std::vector<char> buffer_;
  size_t buffer_pos_ = 0;
  const size_t buffer_size_;
  const size_t flush_event_count_;

  // statistics
  std::atomic<size_t> event_count_{0};
  std::atomic<size_t> flush_count_{0};
  std::atomic<size_t> bytes_written_{0};
};

} // namespace w1::util