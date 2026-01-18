#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <QBDI.h>
#include <redlog.hpp>

#include "rewind_config.hpp"

#include "w1runtime/module_registry.hpp"
#include "w1rewind/record/trace_writer.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/types.hpp"
#include "w1runtime/register_capture.hpp"

namespace w1rewind {

class rewind_recorder {
public:
  rewind_recorder(rewind_config config, std::shared_ptr<w1::rewind::trace_writer> writer);

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  void on_basic_block_entry(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  void on_instruction_post(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void on_memory(
      w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

private:
  struct pending_snapshot {
    uint64_t snapshot_id = 0;
    std::vector<w1::rewind::register_delta> registers;
    std::vector<uint8_t> stack_snapshot;
    std::string reason;
  };

  struct pending_instruction {
    w1::rewind::instruction_record record;
    std::vector<w1::rewind::register_delta> register_deltas;
    std::vector<w1::rewind::memory_access_record> memory_accesses;
    std::optional<pending_snapshot> snapshot;
  };

  struct thread_state {
    uint64_t thread_id = 0;
    std::string thread_name;
    uint64_t sequence = 0;
    uint64_t flow_count = 0;
    uint64_t snapshot_count = 0;
    uint64_t flow_since_snapshot = 0;
    uint64_t memory_events = 0;
    bool thread_start_written = false;
    std::optional<w1::util::register_state> last_registers;
    std::optional<pending_instruction> pending;
  };

  bool ensure_writer_ready(w1::trace_context& ctx);
  bool ensure_tables(w1::trace_context& ctx, const QBDI::GPRState* gpr);
  void flush_pending(thread_state& state);
  void capture_register_deltas(
      thread_state& state, const w1::util::register_state& regs, std::vector<w1::rewind::register_delta>& out
  );
  std::vector<w1::rewind::register_delta> capture_register_snapshot(const w1::util::register_state& regs) const;
  std::vector<uint8_t> capture_stack_snapshot(w1::trace_context& ctx, const w1::util::register_state& regs) const;
  std::optional<pending_snapshot> maybe_capture_snapshot(
      w1::trace_context& ctx, thread_state& state, const w1::util::register_state& regs
  );
  void update_register_table(const w1::util::register_state& regs);
  void update_module_table(const w1::runtime::module_registry& modules);
  std::pair<uint64_t, uint64_t> map_instruction_address(const w1::runtime::module_registry& modules, uint64_t address);
  uint64_t ensure_block_id(uint64_t module_id, uint64_t module_offset, uint32_t size);
  void append_memory_access(
      thread_state& state, w1::trace_context& ctx, const w1::memory_event& event, w1::rewind::memory_access_kind kind
  );

  rewind_config config_{};
  std::shared_ptr<w1::rewind::trace_writer> writer_;
  redlog::logger log_ = redlog::get_logger("w1rewind.recorder");
  bool writer_ready_ = false;
  bool tables_written_ = false;
  bool instruction_flow_ = false;

  struct block_key {
    uint64_t module_id = 0;
    uint64_t module_offset = 0;
    uint32_t size = 0;

    bool operator==(const block_key& other) const {
      return module_id == other.module_id && module_offset == other.module_offset && size == other.size;
    }
  };

  struct block_key_hash {
    size_t operator()(const block_key& key) const noexcept {
      size_t seed = std::hash<uint64_t>{}(key.module_id);
      seed ^= std::hash<uint64_t>{}(key.module_offset) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
      seed ^= std::hash<uint32_t>{}(key.size) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
      return seed;
    }
  };

  std::vector<std::string> register_table_;
  std::unordered_map<std::string, uint16_t> register_ids_;
  std::vector<w1::rewind::module_record> module_table_;
  std::unordered_map<uint64_t, uint64_t> module_id_by_base_;
  std::unordered_map<block_key, uint64_t, block_key_hash> block_ids_;
  uint64_t next_block_id_ = 1;
  std::unordered_map<uint64_t, thread_state> threads_;
};

} // namespace w1rewind
