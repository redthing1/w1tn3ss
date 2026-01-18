#pragma once

#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

struct trace_chunk_info {
  uint64_t file_offset = 0;
  uint32_t compressed_size = 0;
  uint32_t uncompressed_size = 0;
};

struct trace_record_location {
  uint32_t chunk_index = 0;
  uint32_t record_offset = 0;
};

class trace_reader {
public:
  explicit trace_reader(std::string path);

  bool open();
  void close();
  void reset();

  bool read_next(trace_record& record);
  bool read_next(trace_record& record, trace_record_location* location);
  bool seek_to_chunk(const trace_chunk_info& chunk, uint32_t chunk_index, uint32_t record_offset);

  const trace_header& header() const { return header_; }
  const std::optional<target_info_record>& target_info() const { return target_info_; }
  const std::vector<register_spec>& register_specs() const { return register_specs_; }
  const std::vector<std::string>& register_table() const { return register_table_; }
  const std::vector<module_record>& module_table() const { return module_table_; }
  const std::vector<memory_region_record>& memory_map() const { return memory_map_; }
  const std::vector<block_definition_record>& block_table() const { return block_table_; }
  const std::string& error() const { return error_; }
  const std::optional<trace_chunk_info>& last_chunk_info() const { return last_chunk_info_; }
  uint32_t current_chunk_index() const { return current_chunk_index_; }

private:
  bool read_header();
  bool read_chunk();
  bool read_chunk_at(uint64_t file_offset, uint32_t chunk_index, const trace_chunk_info* expected);
  bool read_stream_bytes(void* data, size_t size);
  bool read_bytes(void* data, size_t size);
  bool read_record_header(record_header& header);

  bool parse_record(const record_header& header, const std::vector<uint8_t>& payload, trace_record& record);

  std::string path_;
  std::ifstream stream_;
  trace_header header_{};
  bool header_read_ = false;
  std::vector<uint8_t> chunk_buffer_{};
  size_t chunk_offset_ = 0;
  uint32_t next_chunk_index_ = 0;
  uint32_t current_chunk_index_ = 0;
  std::optional<trace_chunk_info> last_chunk_info_{};
  std::optional<target_info_record> target_info_{};
  std::vector<register_spec> register_specs_{};
  std::vector<std::string> register_table_{};
  std::vector<module_record> module_table_{};
  std::vector<memory_region_record> memory_map_{};
  std::vector<block_definition_record> block_table_{};
  std::string error_;
};

} // namespace w1::rewind
