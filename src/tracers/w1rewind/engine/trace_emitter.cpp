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
    uint64_t thread_id, uint64_t address, uint32_t size, uint32_t space_id, uint16_t mode_id, uint64_t& sequence_out
) {
  if (!builder_ || !builder_->good()) {
    return false;
  }
  return builder_->emit_block(thread_id, address, size, space_id, mode_id, sequence_out);
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
  if (!builder_->emit_instruction(
          record.thread_id, record.address, record.size, record.space_id, record.mode_id, sequence
      )) {
    return;
  }

  bool capture_regs = config_->registers.deltas || config_->registers.bytes;
  if (capture_regs && !record.register_writes.empty()) {
    w1::rewind::reg_write_record reg_record{};
    reg_record.thread_id = record.thread_id;
    reg_record.sequence = sequence;
    reg_record.regfile_id = 0;
    reg_record.entries = std::move(record.register_writes);
    if (!builder_->emit_reg_write(reg_record)) {
      return;
    }
  }

  if (config_->memory.access != rewind_config::memory_access::none) {
    for (const auto& access : record.memory_accesses) {
      w1::rewind::mem_access_record mem_record{};
      mem_record.thread_id = record.thread_id;
      mem_record.sequence = sequence;
      mem_record.space_id = access.space_id;
      mem_record.op = access.op;
      mem_record.flags = access.flags;
      mem_record.address = access.address;
      mem_record.access_size = access.size;
      mem_record.value = access.data;
      if (!builder_->emit_mem_access(mem_record)) {
        return;
      }
    }
  }

  if (record.snapshot.has_value()) {
    w1::rewind::snapshot_record snapshot{};
    snapshot.thread_id = record.thread_id;
    snapshot.sequence = sequence;
    snapshot.regfile_id = 0;
    snapshot.registers = std::move(record.snapshot->registers);
    snapshot.memory_segments = std::move(record.snapshot->memory_segments);
    builder_->emit_snapshot(snapshot);
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
