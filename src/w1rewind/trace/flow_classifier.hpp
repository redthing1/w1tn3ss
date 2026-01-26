#pragma once

#include <cstdint>
#include <optional>

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

enum class flow_record_kind { instruction, block_exec };

struct flow_record_key {
  flow_record_kind kind = flow_record_kind::instruction;
  uint64_t sequence = 0;
  uint64_t thread_id = 0;
};

inline std::optional<flow_record_key> classify_flow_record(const trace_record& record, bool use_blocks) {
  if (use_blocks) {
    if (const auto* exec = std::get_if<block_exec_record>(&record)) {
      return flow_record_key{flow_record_kind::block_exec, exec->sequence, exec->thread_id};
    }
    return std::nullopt;
  }
  if (const auto* inst = std::get_if<flow_instruction_record>(&record)) {
    return flow_record_key{flow_record_kind::instruction, inst->sequence, inst->thread_id};
  }
  return std::nullopt;
}

} // namespace w1::rewind
