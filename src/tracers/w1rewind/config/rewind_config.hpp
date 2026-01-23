#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "w1instrument/config/tracer_common_config.hpp"
#include "w1rewind/format/trace_format.hpp"
#include "w1base/types.hpp"

namespace w1rewind {

struct rewind_config {
  w1::instrument::config::tracer_common_config common{};
  w1::instrument::config::thread_attach_policy threads =
      w1::instrument::config::thread_attach_policy::main_only;

  struct flow_options {
    enum class flow_mode { instruction, block };
    flow_mode mode = flow_mode::block;
  };

  struct register_options {
    enum class capture_kind { gpr };
    capture_kind capture = capture_kind::gpr;
    bool deltas = false;
    uint64_t snapshot_interval = 0;
    bool bytes = false;
  };

  struct stack_window_options {
    enum class window_mode { none, fixed, frame };
    window_mode mode = window_mode::none;
    uint64_t above_bytes = 512;
    uint64_t below_bytes = 2048;
    uint64_t max_total_bytes = 4096;
  };

  struct stack_snapshot_options {
    uint64_t interval = 0;
  };

  enum class memory_access { none, reads, writes, reads_writes };
  enum class memory_filter_kind { all, ranges, stack_window };

  struct memory_options {
    memory_access access = memory_access::none;
    bool values = false;
    uint32_t max_value_bytes = 32;
    std::vector<memory_filter_kind> filters = {memory_filter_kind::all};
    std::vector<w1::address_range> ranges{};
  };

  flow_options flow{};
  register_options registers{};
  stack_window_options stack_window{};
  stack_snapshot_options stack_snapshots{};
  memory_options memory{};
  std::string output_path;
  bool compress_trace = false;
  uint32_t chunk_size = w1::rewind::k_trace_chunk_bytes;

  static rewind_config from_environment(std::string& error);
  bool validate(std::string& error) const;
};

} // namespace w1rewind
