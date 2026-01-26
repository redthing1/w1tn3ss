#pragma once

#include <optional>
#include <string_view>

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

struct trace_chunk_info {
  uint64_t file_offset = 0;
  uint32_t compressed_size = 0;
  uint32_t uncompressed_size = 0;
  compression codec = compression::none;
  uint16_t flags = 0;
};

struct trace_record_location {
  uint32_t chunk_index = 0;
  uint32_t record_offset = 0;
};

class trace_record_stream {
public:
  virtual ~trace_record_stream() = default;
  virtual bool open() = 0;
  virtual void close() = 0;
  virtual bool read_next(trace_record& record, trace_record_location* location) = 0;
  virtual bool seek_to_location(const trace_record_location& location) = 0;
  virtual const file_header& header() const = 0;
  virtual const std::optional<trace_chunk_info>& last_chunk_info() const = 0;
  virtual std::string_view error() const = 0;
};

} // namespace w1::rewind
