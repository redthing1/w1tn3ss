#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <redlog.hpp>

#include "memory_access_builder.hpp"
#include "memory_filter.hpp"
#include "module_table_builder.hpp"
#include "register_delta_builder.hpp"
#include "register_schema.hpp"
#include "rewind_config.hpp"
#include "snapshot_builder.hpp"
#include "trace_emitter.hpp"
#include "w1base/arch_spec.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/types.hpp"
#include "w1rewind/record/trace_builder.hpp"
#include "w1rewind/trace/record_sink.hpp"

namespace w1::util {
class register_state;
} // namespace w1::util

namespace w1rewind {

class recording_engine {
public:
  recording_engine(rewind_config config, std::shared_ptr<w1::rewind::trace_record_sink> sink);

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  void on_basic_block_entry(
      w1::trace_context& ctx, const w1::basic_block_event& event, const w1::util::register_state* regs
  );
  void on_instruction_post(
      w1::trace_context& ctx, const w1::instruction_event& event, const w1::util::register_state* regs
  );
  void on_memory(w1::trace_context& ctx, const w1::memory_event& event, const w1::util::register_state* regs);
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

private:
  struct thread_state {
    uint64_t thread_id = 0;
    std::string thread_name;
    uint64_t flow_count = 0;
    uint64_t memory_events = 0;
    snapshot_state snapshot_state{};
    std::optional<w1::util::register_state> last_registers;
    std::optional<pending_instruction> pending;
  };

  bool ensure_builder_ready(w1::trace_context& ctx, const w1::util::register_state* regs);
  void update_module_table(const w1::runtime::module_registry& modules);
  uint32_t resolve_block_flags(const w1::util::register_state* regs) const;
  uint32_t resolve_instruction_flags(const w1::util::register_state* regs) const;
  bool build_thread_start(thread_state& state);

  rewind_config config_{};
  std::shared_ptr<w1::rewind::trace_record_sink> sink_;
  std::unique_ptr<w1::rewind::trace_builder> builder_;
  std::unique_ptr<trace_emitter> emitter_;
  redlog::logger log_ = redlog::get_logger("w1rewind.recorder");
  bool builder_ready_ = false;
  bool instruction_flow_ = false;
  memory_filter memory_filter_;
  w1::arch::arch_spec arch_spec_{};

  register_schema register_schema_;
  std::vector<w1::rewind::module_record> module_table_;
  std::unordered_map<uint64_t, thread_state> threads_;
};

} // namespace w1rewind
