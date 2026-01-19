#include "trace_builder.hpp"

#include <algorithm>

namespace w1::rewind {

namespace {

bool validate_register_specs(const std::vector<register_spec>& specs, std::string& error) {
  if (specs.empty()) {
    error = "register specs missing";
    return false;
  }

  uint16_t max_id = 0;
  for (const auto& spec : specs) {
    if (spec.name.empty()) {
      error = "register spec name missing";
      return false;
    }
    if (spec.bits == 0) {
      error = "register spec bits missing";
      return false;
    }
    max_id = std::max(max_id, spec.reg_id);
  }

  size_t expected = static_cast<size_t>(max_id) + 1;
  if (expected != specs.size()) {
    error = "register ids must be contiguous";
    return false;
  }

  std::vector<bool> seen(expected, false);
  for (const auto& spec : specs) {
    if (spec.reg_id >= expected) {
      error = "register id out of range";
      return false;
    }
    if (seen[spec.reg_id]) {
      error = "duplicate register id";
      return false;
    }
    seen[spec.reg_id] = true;
  }

  return true;
}

} // namespace

trace_builder::trace_builder(trace_builder_config config) : config_(std::move(config)) {}

bool trace_builder::begin_trace(
    const w1::arch::arch_spec& arch,
    const target_info_record& target,
    const std::vector<register_spec>& register_specs
) {
  if (started_) {
    error_ = "trace already started";
    return false;
  }
  if (!config_.writer) {
    error_ = "trace writer missing";
    return false;
  }
  if (!config_.writer->good()) {
    error_ = "trace writer not ready";
    return false;
  }
  if (arch.arch_family == w1::arch::family::unknown || arch.arch_mode == w1::arch::mode::unknown) {
    error_ = "trace arch spec missing";
    return false;
  }
  if (arch.pointer_bits == 0 || (arch.pointer_bits % 8) != 0) {
    error_ = "trace pointer bits invalid";
    return false;
  }
  if (arch.arch_byte_order == w1::arch::byte_order::unknown) {
    error_ = "trace byte order missing";
    return false;
  }
  if (!validate_register_specs(register_specs, error_)) {
    return false;
  }

  target_info_ = target;
  register_specs_ = register_specs;

  trace_header header{};
  header.arch = arch;
  header.flags = 0;
  if (config_.options.record_instructions) {
    header.flags |= trace_flag_instructions;
  } else {
    header.flags |= trace_flag_blocks;
  }
  if (config_.options.record_register_deltas) {
    header.flags |= trace_flag_register_deltas;
  }
  if (config_.options.record_memory_access) {
    header.flags |= trace_flag_memory_access;
    if (config_.options.record_memory_values) {
      header.flags |= trace_flag_memory_values;
    }
  }
  if (config_.options.record_snapshots) {
    header.flags |= trace_flag_snapshots;
  }
  if (config_.options.record_stack_snapshot) {
    header.flags |= trace_flag_stack_snapshot;
  }

  if (!config_.writer->write_header(header)) {
    error_ = "failed to write trace header";
    return false;
  }

  if (!config_.writer->write_target_info(target_info_)) {
    error_ = "failed to write target info";
    return false;
  }

  register_spec_record spec_record{};
  spec_record.registers = register_specs_;
  if (!config_.writer->write_register_spec(spec_record)) {
    error_ = "failed to write register specs";
    return false;
  }

  started_ = true;
  if (module_table_pending_) {
    if (!write_module_table()) {
      return false;
    }
  }
  if (memory_map_pending_) {
    if (!write_memory_map()) {
      return false;
    }
  }

  return true;
}

bool trace_builder::set_module_table(std::vector<module_record> modules) {
  modules_ = std::move(modules);
  module_table_pending_ = true;
  if (!started_) {
    return true;
  }
  return write_module_table();
}

bool trace_builder::set_memory_map(std::vector<memory_region_record> regions) {
  memory_map_ = std::move(regions);
  memory_map_pending_ = true;
  if (!started_) {
    return true;
  }
  return write_memory_map();
}

bool trace_builder::begin_thread(uint64_t thread_id, std::string name) {
  if (!ensure_trace_started()) {
    return false;
  }
  auto& state = threads_[thread_id];
  if (!name.empty() && state.name.empty()) {
    state.name = std::move(name);
  }
  return ensure_thread_started(state, thread_id);
}

bool trace_builder::end_thread(uint64_t thread_id) {
  if (!ensure_trace_started()) {
    return false;
  }
  auto& state = threads_[thread_id];
  if (!ensure_thread_started(state, thread_id)) {
    return false;
  }
  if (state.ended) {
    return true;
  }
  thread_end_record end{};
  end.thread_id = thread_id;
  if (!config_.writer->write_thread_end(end)) {
    error_ = "failed to write thread end";
    return false;
  }
  state.ended = true;
  return true;
}

bool trace_builder::emit_instruction(
    uint64_t thread_id,
    uint64_t address,
    uint32_t size,
    uint32_t flags,
    uint64_t& sequence_out
) {
  if (!ensure_trace_started()) {
    return false;
  }
  if (!config_.options.record_instructions) {
    error_ = "instruction flow not enabled";
    return false;
  }
  auto& state = threads_[thread_id];
  if (!ensure_thread_started(state, thread_id)) {
    return false;
  }

  instruction_record record{};
  record.sequence = state.next_sequence++;
  record.thread_id = thread_id;
  record.address = address;
  record.size = size;
  record.flags = flags;

  if (!config_.writer->write_instruction(record)) {
    error_ = "failed to write instruction record";
    return false;
  }

  sequence_out = record.sequence;
  return true;
}

bool trace_builder::emit_block(
    uint64_t thread_id,
    uint64_t address,
    uint32_t size,
    uint32_t flags,
    uint64_t& sequence_out
) {
  if (!ensure_trace_started()) {
    return false;
  }
  if (config_.options.record_instructions) {
    error_ = "block flow not enabled";
    return false;
  }
  auto& state = threads_[thread_id];
  if (!ensure_thread_started(state, thread_id)) {
    return false;
  }

  block_key key{};
  key.address = address;
  key.size = size;
  key.flags = flags;

  uint64_t block_id = 0;
  auto it = block_ids_.find(key);
  if (it == block_ids_.end()) {
    block_id = next_block_id_++;
    block_ids_[key] = block_id;
    block_definition_record def{};
    def.block_id = block_id;
    def.address = address;
    def.size = size;
    def.flags = flags;
    if (!config_.writer->write_block_definition(def)) {
      error_ = "failed to write block definition";
      return false;
    }
  } else {
    block_id = it->second;
  }

  block_exec_record exec{};
  exec.sequence = state.next_sequence++;
  exec.thread_id = thread_id;
  exec.block_id = block_id;
  if (!config_.writer->write_block_exec(exec)) {
    error_ = "failed to write block exec";
    return false;
  }

  sequence_out = exec.sequence;
  return true;
}

bool trace_builder::emit_register_deltas(
    uint64_t thread_id,
    uint64_t sequence,
    std::span<const register_delta> deltas
) {
  if (!config_.options.record_register_deltas || deltas.empty()) {
    return true;
  }
  if (!ensure_trace_started()) {
    return false;
  }

  register_delta_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.deltas.assign(deltas.begin(), deltas.end());

  if (!config_.writer->write_register_deltas(record)) {
    error_ = "failed to write register deltas";
    return false;
  }
  return true;
}

bool trace_builder::emit_register_bytes(
    uint64_t thread_id,
    uint64_t sequence,
    std::span<const register_bytes_entry> entries,
    std::span<const uint8_t> data
) {
  if (!config_.options.record_register_deltas || entries.empty()) {
    return true;
  }
  if (!ensure_trace_started()) {
    return false;
  }
  if (data.empty()) {
    error_ = "register bytes data missing";
    return false;
  }

  for (const auto& entry : entries) {
    if (entry.reg_id >= register_specs_.size()) {
      error_ = "register bytes reg_id out of range";
      return false;
    }
    const auto& spec = register_specs_[entry.reg_id];
    if (spec.value_kind != register_value_kind::bytes) {
      error_ = "register bytes value_kind mismatch";
      return false;
    }
    uint32_t expected = (spec.bits + 7u) / 8u;
    if (entry.size != expected) {
      error_ = "register bytes size mismatch";
      return false;
    }
    uint64_t end = static_cast<uint64_t>(entry.offset) + static_cast<uint64_t>(entry.size);
    if (end > data.size()) {
      error_ = "register bytes data out of range";
      return false;
    }
  }

  register_bytes_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.entries.assign(entries.begin(), entries.end());
  record.data.assign(data.begin(), data.end());

  if (!config_.writer->write_register_bytes(record)) {
    error_ = "failed to write register bytes";
    return false;
  }
  return true;
}

bool trace_builder::emit_memory_access(
    uint64_t thread_id,
    uint64_t sequence,
    memory_access_kind kind,
    uint64_t address,
    uint32_t size,
    bool value_known,
    bool value_truncated,
    std::span<const uint8_t> data
) {
  if (!config_.options.record_memory_access) {
    return true;
  }
  if (!ensure_trace_started()) {
    return false;
  }

  memory_access_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.kind = kind;
  record.address = address;
  record.size = size;

  if (!config_.options.record_memory_values) {
    record.value_known = false;
    record.value_truncated = false;
  } else {
    record.value_known = value_known;
    record.value_truncated = value_truncated;
    record.data.assign(data.begin(), data.end());
  }

  if (!config_.writer->write_memory_access(record)) {
    error_ = "failed to write memory access";
    return false;
  }
  return true;
}

bool trace_builder::emit_snapshot(
    uint64_t thread_id,
    uint64_t sequence,
    uint64_t snapshot_id,
    std::span<const register_delta> registers,
    std::span<const uint8_t> stack_snapshot,
    std::string reason
) {
  if (!config_.options.record_snapshots && !config_.options.record_stack_snapshot) {
    return true;
  }
  if (!ensure_trace_started()) {
    return false;
  }

  snapshot_record record{};
  record.snapshot_id = snapshot_id;
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.registers.assign(registers.begin(), registers.end());
  record.stack_snapshot.assign(stack_snapshot.begin(), stack_snapshot.end());
  record.reason = std::move(reason);

  if (!config_.writer->write_snapshot(record)) {
    error_ = "failed to write snapshot";
    return false;
  }
  return true;
}

void trace_builder::flush() {
  if (config_.writer) {
    config_.writer->flush();
  }
}

bool trace_builder::good() const {
  if (!config_.writer) {
    return false;
  }
  return config_.writer->good();
}

bool trace_builder::ensure_trace_started() {
  if (started_) {
    return true;
  }
  error_ = "trace not started";
  return false;
}

bool trace_builder::ensure_thread_started(thread_state& state, uint64_t thread_id) {
  if (state.started) {
    return true;
  }

  thread_start_record start{};
  start.thread_id = thread_id;
  start.name = state.name;
  if (!config_.writer->write_thread_start(start)) {
    error_ = "failed to write thread start";
    return false;
  }
  state.started = true;
  return true;
}

bool trace_builder::write_module_table() {
  if (module_table_written_) {
    return true;
  }
  if (!ensure_trace_started()) {
    return false;
  }
  module_table_record record{};
  record.modules = modules_;
  if (!config_.writer->write_module_table(record)) {
    error_ = "failed to write module table";
    return false;
  }
  module_table_written_ = true;
  module_table_pending_ = false;
  return true;
}

bool trace_builder::write_memory_map() {
  if (memory_map_written_) {
    return true;
  }
  if (!ensure_trace_started()) {
    return false;
  }
  memory_map_record record{};
  record.regions = memory_map_;
  if (!config_.writer->write_memory_map(record)) {
    error_ = "failed to write memory map";
    return false;
  }
  memory_map_written_ = true;
  memory_map_pending_ = false;
  return true;
}

} // namespace w1::rewind
