#pragma once

#include <memory>

#include "trace_types.hpp"

namespace w1::rewind {

class trace_source {
public:
  virtual ~trace_source() = default;

  virtual bool initialize() = 0;
  virtual void close() = 0;
  virtual bool read_event(trace_event& event) = 0;
  virtual void reset() = 0;
  virtual bool good() const = 0;
};

using trace_source_ptr = std::shared_ptr<trace_source>;

} // namespace w1::rewind
