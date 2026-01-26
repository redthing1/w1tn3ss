#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "config/rewind_config.hpp"
#include "thread/memory_access_builder.hpp"
#include "thread/snapshot_builder.hpp"
#include "w1rewind/record/trace_builder.hpp"

namespace w1rewind {

struct pending_instruction {
  uint64_t thread_id = 0;
  uint64_t address = 0;
  uint32_t size = 0;
  uint32_t space_id = 0;
  uint16_t mode_id = 0;
  std::vector<w1::rewind::reg_write_entry> register_writes;
  std::vector<pending_memory_access> memory_accesses;
  std::optional<pending_snapshot> snapshot;
};

class trace_emitter {
public:
  trace_emitter(w1::rewind::trace_builder* builder, const rewind_config& config, bool instruction_flow);

  bool begin_thread(uint64_t thread_id, const std::string& name);
  bool emit_block(
      uint64_t thread_id, uint64_t address, uint32_t size, uint32_t space_id, uint16_t mode_id,
      uint64_t& sequence_out
  );
  void flush_pending(std::optional<pending_instruction>& pending);
  void finalize_thread(uint64_t thread_id, const std::string& name);

private:
  w1::rewind::trace_builder* builder_ = nullptr;
  const rewind_config* config_ = nullptr;
  bool instruction_flow_ = false;
};

} // namespace w1rewind
