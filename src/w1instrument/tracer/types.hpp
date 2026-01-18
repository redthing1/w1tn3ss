#pragma once

#include <cstdint>

#include "w1base/types.hpp"

namespace w1 {

struct instruction_event {
  uint64_t address;
  uint32_t size;
  uint64_t thread_id;
};

struct basic_block_event {
  uint64_t address;
  uint32_t size;
  uint64_t thread_id;
};

struct sequence_event {
  uint64_t start;
  uint64_t end;
  uint64_t thread_id;
};

struct exec_transfer_event {
  uint64_t source_address;
  uint64_t target_address;
  uint64_t thread_id;
};

struct memory_event {
  uint64_t instruction_address;
  uint64_t address;
  uint32_t size;
  uint32_t flags;
  uint64_t value;
  bool is_read;
  bool is_write;
  bool value_valid;
  uint64_t thread_id;
};

struct thread_event {
  uint64_t thread_id;
  const char* name;
};

struct trace_summary {
  uint64_t instructions;
  uint64_t basic_blocks;
  uint64_t memory_events;
};

} // namespace w1
