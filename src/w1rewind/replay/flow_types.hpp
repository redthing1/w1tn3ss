#pragma once

#include <cstdint>
#include <string>

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

struct flow_step {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  uint32_t space_id = 0;
  uint16_t mode_id = 0;
  uint32_t size = 0;
  uint64_t address = 0;
  uint64_t block_id = 0;
  uint32_t flags = 0;
  bool is_block = false;
};

class flow_record_observer {
public:
  virtual ~flow_record_observer() = default;
  virtual bool on_record(const trace_record& record, uint64_t active_thread_id, std::string& error) = 0;
};

} // namespace w1::rewind
