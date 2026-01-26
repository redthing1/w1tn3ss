#pragma once

#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/trace/record_sink.hpp"

namespace w1::rewind {

struct trace_file_writer_config {
  std::string path;
  redlog::logger log;
  compression codec = compression::none;
  uint32_t chunk_size = 0;
};

class trace_file_writer : public trace_record_sink {
public:
  explicit trace_file_writer(trace_file_writer_config config);
  ~trace_file_writer() override;

  bool open();
  void close();
  bool good() const override { return good_; }

  const std::string& path() const { return path_; }

  bool write_header(const file_header& header) override;
  bool write_record(const record_header& header, std::span<const uint8_t> payload) override;
  void flush() override;

private:
  bool flush_chunk_locked();
  void write_u16(uint16_t value);
  void write_u32(uint32_t value);
  void write_u64(uint64_t value);
  void write_bytes(const void* data, size_t size);
  void mark_failure();
  std::string make_default_path() const;

  trace_file_writer_config config_;
  std::ofstream stream_;
  std::string path_;
  bool good_ = false;
  bool header_written_ = false;
  uint32_t chunk_size_ = 0;
  std::vector<uint8_t> chunk_buffer_;
  std::vector<uint8_t> chunk_encoded_;
  std::vector<chunk_dir_entry> chunk_directory_;
  std::mutex mutex_;
};

std::shared_ptr<trace_file_writer> make_trace_file_writer(trace_file_writer_config config);

} // namespace w1::rewind
