#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "trace_format.hpp"

namespace w1::rewind {

class trace_reader {
public:
  explicit trace_reader(std::string path);

  bool open();
  void close();
  void reset();

  bool read_next(trace_record& record);

  const trace_header& header() const { return header_; }
  const std::vector<std::string>& register_table() const { return register_table_; }
  const std::vector<module_record>& module_table() const { return module_table_; }
  const std::vector<block_definition_record>& block_table() const { return block_table_; }
  const std::string& error() const { return error_; }

private:
  bool read_header();
  bool read_chunk();
  bool read_stream_bytes(void* data, size_t size);
  bool read_bytes(void* data, size_t size);
  bool read_u8(uint8_t& value);
  bool read_u16(uint16_t& value);
  bool read_u32(uint32_t& value);
  bool read_u64(uint64_t& value);
  bool read_record_header(record_header& header);

  bool parse_record(const record_header& header, const std::vector<uint8_t>& payload, trace_record& record);

  std::string path_;
  std::ifstream stream_;
  trace_header header_{};
  bool header_read_ = false;
  std::vector<uint8_t> chunk_buffer_{};
  size_t chunk_offset_ = 0;
  std::vector<std::string> register_table_{};
  std::vector<module_record> module_table_{};
  std::vector<block_definition_record> block_table_{};
  std::string error_;
};

} // namespace w1::rewind
