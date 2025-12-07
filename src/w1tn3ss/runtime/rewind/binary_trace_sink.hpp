#pragma once

#include <fstream>
#include <mutex>
#include <string>

#include <redlog.hpp>

#include "trace_sink.hpp"

namespace w1::rewind {

struct binary_trace_sink_config {
  std::string path;
  redlog::logger log;
};

class binary_trace_sink : public trace_sink {
public:
  explicit binary_trace_sink(binary_trace_sink_config config);
  ~binary_trace_sink() override;

  bool initialize() override;
  void close() override;
  bool write_event(const trace_event& event) override;
  void flush() override;
  bool good() const override { return good_; }

  const std::string& path() const { return path_; }

private:
  enum class event_type : uint8_t { instruction = 1, boundary = 2 };

  struct file_header {
    char magic[8];
    uint32_t version = 3;
    uint32_t flags = 0;
    uint32_t architecture = 0;
    uint32_t reserved = 0;
  };

  std::string make_default_path() const;
  void write_header();
  void write_u8(uint8_t value);
  void write_u16(uint16_t value);
  void write_u32(uint32_t value);
  void write_u64(uint64_t value);
  void write_bytes(const void* data, size_t size);
  void write_string(const std::string& value);
  void write_memory_list(const std::vector<trace_memory_delta>& accesses);
  void mark_failure();
  uint32_t detect_architecture() const;

  binary_trace_sink_config config_;
  std::ofstream stream_;
  std::string path_;
  bool header_written_ = false;
  bool good_ = false;
  std::mutex mutex_;
};

std::shared_ptr<binary_trace_sink> make_binary_trace_sink(binary_trace_sink_config config);

} // namespace w1::rewind
