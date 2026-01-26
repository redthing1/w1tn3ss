#pragma once

#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "record_stream.hpp"

namespace w1::rewind {

class trace_reader final : public trace_record_stream {
public:
  explicit trace_reader(std::string path);

  bool open() override;
  void close() override;
  void reset();

  bool read_next(trace_record& record);
  bool read_next(trace_record& record, trace_record_location* location) override;
  bool seek_to_location(const trace_record_location& location) override;
  bool seek_to_chunk(const trace_chunk_info& chunk, uint32_t chunk_index, uint32_t record_offset);

  const file_header& header() const override { return header_; }
  std::string_view error() const override { return error_; }
  const std::optional<trace_chunk_info>& last_chunk_info() const override { return last_chunk_info_; }
  uint32_t current_chunk_index() const { return current_chunk_index_; }
  bool has_chunk_directory() const { return has_chunk_directory_; }

private:
  bool read_header();
  bool read_footer();
  bool read_chunk();
  bool read_chunk_at(uint64_t file_offset, uint32_t chunk_index, const trace_chunk_info* expected);
  bool read_stream_bytes(void* data, size_t size);
  bool read_bytes(void* data, size_t size);
  bool read_record_header(record_header& header);
  bool ensure_chunk_info(uint32_t chunk_index);

  bool parse_record(const record_header& header, const std::vector<uint8_t>& payload, trace_record& record);

  std::string path_;
  std::ifstream stream_;
  file_header header_{};
  bool header_read_ = false;
  bool has_chunk_directory_ = false;
  uint64_t header_end_offset_ = 0;
  std::vector<uint8_t> chunk_buffer_{};
  size_t chunk_offset_ = 0;
  uint32_t next_chunk_index_ = 0;
  uint32_t current_chunk_index_ = 0;
  std::optional<trace_chunk_info> last_chunk_info_{};
  std::vector<trace_chunk_info> chunks_{};
  std::string error_;
};

} // namespace w1::rewind
