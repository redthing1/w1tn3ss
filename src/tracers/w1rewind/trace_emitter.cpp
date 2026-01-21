#include "trace_emitter.hpp"

namespace w1rewind {

trace_emitter::trace_emitter(w1::rewind::trace_builder* builder, const rewind_config& config, bool instruction_flow)
    : builder_(builder), config_(&config), instruction_flow_(instruction_flow) {}

bool trace_emitter::begin_thread(uint64_t thread_id, const std::string& name) {
  if (!builder_ || !builder_->good()) {
    return false;
  }
  return builder_->begin_thread(thread_id, name);
}

bool trace_emitter::emit_block(
    uint64_t thread_id, uint64_t address, uint32_t size, uint32_t flags, uint64_t& sequence_out
) {
  if (!builder_ || !builder_->good()) {
    return false;
  }
  return builder_->emit_block(thread_id, address, size, flags, sequence_out);
}

void trace_emitter::flush_pending(std::optional<pending_instruction>& pending) {
  if (!pending.has_value()) {
    return;
  }

  pending_instruction record = std::move(*pending);
  pending.reset();

  if (!instruction_flow_) {
    return;
  }
  if (!builder_ || !builder_->good()) {
    return;
  }

  uint64_t sequence = 0;
  if (!builder_->emit_instruction(record.thread_id, record.address, record.size, record.flags, sequence)) {
    return;
  }

  if (config_->registers.deltas && !record.register_deltas.empty()) {
    if (!builder_->emit_register_deltas(record.thread_id, sequence, record.register_deltas)) {
      return;
    }
  }

  if (config_->memory.access != rewind_config::memory_access::none) {
    for (const auto& access : record.memory_accesses) {
      if (!builder_->emit_memory_access(
              record.thread_id, sequence, access.kind, access.address, access.size, access.value_known,
              access.value_truncated, access.data
          )) {
        return;
      }
    }
  }

  if (record.snapshot.has_value()) {
    builder_->emit_snapshot(
        record.thread_id, sequence, record.snapshot->snapshot_id, record.snapshot->registers,
        record.snapshot->stack_segments, std::move(record.snapshot->reason)
    );
  }
}

void trace_emitter::finalize_thread(uint64_t thread_id, const std::string& name) {
  if (!builder_ || !builder_->good()) {
    return;
  }
  builder_->begin_thread(thread_id, name);
  builder_->end_thread(thread_id);
  builder_->flush();
}

} // namespace w1rewind
