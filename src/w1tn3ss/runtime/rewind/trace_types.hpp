#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace w1::rewind {

enum class trace_event_type : uint8_t {
  instruction = 1,
  boundary = 2,
};

enum trace_boundary_flags : uint32_t {
  trace_boundary_flag_full_register_snapshot = 1u << 0,
};

struct trace_mismatch {
  enum class kind {
    none = 0,
    missing_expected_event,
    unexpected_event,
    address_mismatch,
    size_mismatch,
    register_mismatch,
    memory_mismatch,
  };

  kind type = kind::none;
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  std::string message;
};

struct trace_register_delta {
  std::string name;
  uint64_t value = 0;
};

struct trace_memory_delta {
  uint64_t address = 0;
  uint32_t size = 0;
  bool value_known = false;
  std::vector<uint8_t> data;
};

struct trace_event {
  trace_event_type type = trace_event_type::instruction;
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  uint64_t address = 0;
  uint32_t size = 0;
  std::vector<trace_register_delta> registers;
  std::vector<trace_memory_delta> reads;
  std::vector<trace_memory_delta> writes;
  struct trace_boundary_info {
    uint64_t boundary_id = 0;
    uint32_t flags = 0;
    std::string reason;
  };
  std::optional<trace_boundary_info> boundary;
};

class trace_observer {
public:
  virtual ~trace_observer() = default;
  virtual void on_event(const trace_event& event) = 0;
};

} // namespace w1::rewind
