#pragma once

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

class trace_record_sink {
public:
  virtual ~trace_record_sink() = default;

  virtual bool good() const = 0;
  virtual bool write_header(const file_header& header) = 0;
  virtual bool write_record(const record_header& header, std::span<const uint8_t> payload) = 0;
  virtual void flush() = 0;
};

} // namespace w1::rewind
