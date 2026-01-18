#include "rewind_recorder.hpp"

#include "w1runtime/memory_reader.hpp"

#include <algorithm>

namespace {
w1::rewind::module_perm module_perm_from_qbdi(uint32_t perms) {
  w1::rewind::module_perm out = w1::rewind::module_perm::none;
  if (perms & QBDI::PF_READ) {
    out = out | w1::rewind::module_perm::read;
  }
  if (perms & QBDI::PF_WRITE) {
    out = out | w1::rewind::module_perm::write;
  }
  if (perms & QBDI::PF_EXEC) {
    out = out | w1::rewind::module_perm::exec;
  }
  return out;
}
} // namespace

namespace w1rewind {

rewind_recorder::rewind_recorder(rewind_config config, std::shared_ptr<w1::rewind::trace_writer> writer)
    : config_(std::move(config)), writer_(std::move(writer)), instruction_flow_(config_.requires_instruction_flow()) {}

void rewind_recorder::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  auto& state = threads_[event.thread_id];
  state.thread_id = event.thread_id;
  if (event.name) {
    state.thread_name = event.name;
  }
}

void rewind_recorder::on_basic_block_entry(
    w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) vm;
  (void) state;
  (void) fpr;

  if (instruction_flow_) {
    return;
  }

  auto& thread = threads_[event.thread_id];
  if (thread.thread_id == 0) {
    thread.thread_id = event.thread_id;
  }

  if (!ensure_writer_ready(ctx)) {
    return;
  }

  if (!ensure_tables(ctx, gpr)) {
    return;
  }

  if (!thread.thread_start_written) {
    w1::rewind::thread_start_record start{};
    start.thread_id = thread.thread_id;
    start.name = thread.thread_name;
    if (!writer_->write_thread_start(start)) {
      return;
    }
    thread.thread_start_written = true;
  }

  uint64_t address = event.address;
  uint32_t size = event.size;
  if (address == 0 || size == 0) {
    return;
  }

  auto [module_id, module_offset] = map_instruction_address(ctx.modules(), address);
  uint64_t block_id = ensure_block_id(module_id, module_offset, size);
  if (block_id == 0) {
    return;
  }

  w1::rewind::block_exec_record exec{};
  exec.sequence = thread.sequence++;
  exec.thread_id = thread.thread_id;
  exec.block_id = block_id;
  if (!writer_->write_block_exec(exec)) {
    return;
  }

  thread.flow_count += 1;

  if (config_.snapshot_interval > 0) {
    w1::util::register_state regs = w1::util::register_capturer::capture(gpr);
    auto snapshot = maybe_capture_snapshot(ctx, thread, regs);
    if (snapshot.has_value()) {
      w1::rewind::snapshot_record record{};
      record.snapshot_id = snapshot->snapshot_id;
      record.sequence = exec.sequence;
      record.thread_id = exec.thread_id;
      record.registers = std::move(snapshot->registers);
      record.stack_snapshot = std::move(snapshot->stack_snapshot);
      record.reason = std::move(snapshot->reason);
      writer_->write_snapshot(record);
    }
  }
}

void rewind_recorder::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) fpr;

  if (!instruction_flow_) {
    return;
  }

  auto& state = threads_[event.thread_id];
  if (state.thread_id == 0) {
    state.thread_id = event.thread_id;
  }

  if (!ensure_writer_ready(ctx)) {
    return;
  }

  if (!ensure_tables(ctx, gpr)) {
    return;
  }

  if (!state.thread_start_written) {
    w1::rewind::thread_start_record start{};
    start.thread_id = state.thread_id;
    start.name = state.thread_name;
    if (!writer_->write_thread_start(start)) {
      return;
    }
    state.thread_start_written = true;
  }

  flush_pending(state);

  uint64_t address = event.address;
  uint32_t size = event.size;
  if ((address == 0 || size == 0) && vm) {
    if (const auto* analysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION)) {
      address = analysis->address;
      size = analysis->instSize;
    }
  }

  auto [module_id, module_offset] = map_instruction_address(ctx.modules(), address);

  pending_instruction pending{};
  pending.record.sequence = state.sequence++;
  pending.record.thread_id = state.thread_id;
  pending.record.module_id = module_id;
  pending.record.module_offset = module_offset;
  pending.record.size = size;

  bool need_registers = config_.record_register_deltas || config_.snapshot_interval > 0 || config_.stack_snapshot_bytes > 0;
  w1::util::register_state regs;
  if (need_registers) {
    regs = w1::util::register_capturer::capture(gpr);
  }

  if (config_.record_register_deltas) {
    capture_register_deltas(state, regs, pending.register_deltas);
  }

  state.flow_count += 1;
  if (config_.snapshot_interval > 0) {
    auto snapshot = maybe_capture_snapshot(ctx, state, regs);
    if (snapshot.has_value()) {
      pending.snapshot = std::move(snapshot);
    }
  }

  state.pending = std::move(pending);
}

void rewind_recorder::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) vm;
  (void) gpr;
  (void) fpr;

  if (!instruction_flow_ || !config_.memory.enabled) {
    return;
  }

  auto it = threads_.find(event.thread_id);
  if (it == threads_.end()) {
    return;
  }
  auto& state = it->second;
  if (!state.pending.has_value()) {
    return;
  }
  if (event.size == 0) {
    return;
  }

  if (event.is_read && config_.memory.include_reads) {
    append_memory_access(state, ctx, event, w1::rewind::memory_access_kind::read);
  }
  if (event.is_write) {
    append_memory_access(state, ctx, event, w1::rewind::memory_access_kind::write);
  }
}

void rewind_recorder::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  auto it = threads_.find(event.thread_id);
  if (it == threads_.end()) {
    return;
  }

  auto& state = it->second;
  flush_pending(state);

  if (writer_ && writer_->good()) {
    if (!state.thread_start_written && tables_written_) {
      w1::rewind::thread_start_record start{};
      start.thread_id = state.thread_id;
      start.name = state.thread_name;
      writer_->write_thread_start(start);
      state.thread_start_written = true;
    }
    w1::rewind::thread_end_record end{};
    end.thread_id = state.thread_id;
    writer_->write_thread_end(end);
    writer_->flush();
  }

  log_.inf(
      "rewind stats", redlog::field("thread_id", state.thread_id),
      redlog::field("flow_kind", instruction_flow_ ? "instructions" : "blocks"),
      redlog::field("flow_events", state.flow_count), redlog::field("snapshots", state.snapshot_count),
      redlog::field("memory_events", state.memory_events)
  );
}

bool rewind_recorder::ensure_writer_ready(w1::trace_context& ctx) {
  (void) ctx;
  if (writer_ready_) {
    return true;
  }
  if (!writer_) {
    log_.err("trace writer missing");
    return false;
  }
  if (!writer_->good()) {
    log_.err("trace writer not ready");
    return false;
  }

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();

  if (instruction_flow_) {
    header.flags |= w1::rewind::trace_flag_instructions;
  } else {
    header.flags |= w1::rewind::trace_flag_blocks;
  }
  if (config_.record_register_deltas) {
    header.flags |= w1::rewind::trace_flag_register_deltas;
  }
  if (config_.memory.enabled) {
    header.flags |= w1::rewind::trace_flag_memory_access;
    if (config_.memory.include_values) {
      header.flags |= w1::rewind::trace_flag_memory_values;
    }
  }
  if (config_.snapshot_interval > 0) {
    header.flags |= w1::rewind::trace_flag_snapshots;
  }
  if (config_.stack_snapshot_bytes > 0) {
    header.flags |= w1::rewind::trace_flag_stack_snapshot;
  }

  if (!writer_->write_header(header)) {
    return false;
  }

  writer_ready_ = true;
  return true;
}

bool rewind_recorder::ensure_tables(w1::trace_context& ctx, const QBDI::GPRState* gpr) {
  if (tables_written_) {
    return true;
  }
  if (!gpr) {
    log_.err("missing gpr state for register table");
    return false;
  }

  w1::util::register_state regs = w1::util::register_capturer::capture(gpr);
  update_register_table(regs);
  ctx.modules().refresh();
  update_module_table(ctx.modules());

  w1::rewind::register_table_record reg_table{};
  reg_table.names = register_table_;
  if (!writer_->write_register_table(reg_table)) {
    return false;
  }

  w1::rewind::module_table_record mod_table{};
  mod_table.modules = module_table_;
  if (!writer_->write_module_table(mod_table)) {
    return false;
  }

  tables_written_ = true;
  return true;
}

void rewind_recorder::flush_pending(thread_state& state) {
  if (!state.pending.has_value()) {
    return;
  }

  pending_instruction pending = std::move(*state.pending);
  state.pending.reset();

  if (instruction_flow_) {
    if (!writer_->write_instruction(pending.record)) {
      return;
    }
  }

  if (config_.record_register_deltas && !pending.register_deltas.empty()) {
    w1::rewind::register_delta_record deltas{};
    deltas.sequence = pending.record.sequence;
    deltas.thread_id = pending.record.thread_id;
    deltas.deltas = std::move(pending.register_deltas);
    if (!writer_->write_register_deltas(deltas)) {
      return;
    }
  }

  if (config_.memory.enabled) {
    for (auto& access : pending.memory_accesses) {
      if (!writer_->write_memory_access(access)) {
        return;
      }
    }
  }

  if (pending.snapshot.has_value() && config_.snapshot_interval > 0) {
    w1::rewind::snapshot_record record{};
    record.snapshot_id = pending.snapshot->snapshot_id;
    record.sequence = pending.record.sequence;
    record.thread_id = pending.record.thread_id;
    record.registers = std::move(pending.snapshot->registers);
    record.stack_snapshot = std::move(pending.snapshot->stack_snapshot);
    record.reason = std::move(pending.snapshot->reason);
    writer_->write_snapshot(record);
  }
}

void rewind_recorder::capture_register_deltas(
    thread_state& state, const w1::util::register_state& regs, std::vector<w1::rewind::register_delta>& out
) {
  const auto& current = regs.get_register_map();
  const auto* previous = state.last_registers ? &state.last_registers->get_register_map() : nullptr;

  out.clear();
  out.reserve(register_table_.size());

  for (const auto& name : register_table_) {
    auto current_it = current.find(name);
    if (current_it == current.end()) {
      continue;
    }
    bool changed = true;
    if (previous) {
      auto previous_it = previous->find(name);
      if (previous_it != previous->end() && previous_it->second == current_it->second) {
        changed = false;
      }
    }
    if (!changed) {
      continue;
    }

    auto id_it = register_ids_.find(name);
    if (id_it == register_ids_.end()) {
      continue;
    }

    w1::rewind::register_delta delta{};
    delta.reg_id = id_it->second;
    delta.value = current_it->second;
    out.push_back(delta);
  }

  state.last_registers = regs;
}

std::vector<w1::rewind::register_delta> rewind_recorder::capture_register_snapshot(
    const w1::util::register_state& regs
) const {
  std::vector<w1::rewind::register_delta> out;
  const auto& current = regs.get_register_map();
  out.reserve(register_table_.size());

  for (const auto& name : register_table_) {
    auto current_it = current.find(name);
    if (current_it == current.end()) {
      continue;
    }

    auto id_it = register_ids_.find(name);
    if (id_it == register_ids_.end()) {
      continue;
    }

    w1::rewind::register_delta delta{};
    delta.reg_id = id_it->second;
    delta.value = current_it->second;
    out.push_back(delta);
  }

  return out;
}

std::vector<uint8_t> rewind_recorder::capture_stack_snapshot(
    w1::trace_context& ctx, const w1::util::register_state& regs
) const {
  if (config_.stack_snapshot_bytes == 0) {
    return {};
  }
  if (regs.get_register_map().empty()) {
    return {};
  }
  uint64_t sp = regs.get_stack_pointer();
  if (sp == 0) {
    return {};
  }

  auto layout = w1::rewind::compute_stack_snapshot_layout(sp, config_.stack_snapshot_bytes);
  if (layout.size == 0) {
    return {};
  }
  auto bytes = ctx.memory().read_bytes(layout.base, static_cast<size_t>(layout.size));
  if (!bytes.has_value()) {
    return {};
  }
  return *bytes;
}

std::optional<rewind_recorder::pending_snapshot> rewind_recorder::maybe_capture_snapshot(
    w1::trace_context& ctx, thread_state& state, const w1::util::register_state& regs
) {
  if (config_.snapshot_interval == 0) {
    return std::nullopt;
  }

  state.flow_since_snapshot += 1;
  if (state.flow_since_snapshot < config_.snapshot_interval) {
    return std::nullopt;
  }
  state.flow_since_snapshot = 0;

  pending_snapshot snapshot{};
  snapshot.snapshot_id = state.snapshot_count++;
  snapshot.registers = capture_register_snapshot(regs);
  snapshot.stack_snapshot = capture_stack_snapshot(ctx, regs);
  snapshot.reason = "interval";
  return snapshot;
}

void rewind_recorder::update_register_table(const w1::util::register_state& regs) {
  register_table_ = regs.get_register_names();
  register_ids_.clear();
  for (size_t i = 0; i < register_table_.size(); ++i) {
    register_ids_[register_table_[i]] = static_cast<uint16_t>(i);
  }
}

void rewind_recorder::update_module_table(const w1::runtime::module_registry& modules) {
  module_table_.clear();
  module_id_by_base_.clear();

  auto list = modules.list_modules();
  module_table_.reserve(list.size());

  uint64_t next_id = 1;
  for (const auto& module : list) {
    w1::rewind::module_record record{};
    record.id = next_id++;
    record.base = module.base_address;
    record.size = module.size;
    record.permissions = module_perm_from_qbdi(module.permissions);
    record.path = module.path.empty() ? module.name : module.path;
    module_id_by_base_[module.base_address] = record.id;
    module_table_.push_back(std::move(record));
  }
}

std::pair<uint64_t, uint64_t> rewind_recorder::map_instruction_address(
    const w1::runtime::module_registry& modules, uint64_t address
) {
  const auto* module = modules.find_containing(address);
  if (!module) {
    return {0, address};
  }
  auto it = module_id_by_base_.find(module->base_address);
  if (it == module_id_by_base_.end()) {
    return {0, address};
  }
  return {it->second, address - module->base_address};
}

uint64_t rewind_recorder::ensure_block_id(uint64_t module_id, uint64_t module_offset, uint32_t size) {
  block_key key{};
  key.module_id = module_id;
  key.module_offset = module_offset;
  key.size = size;

  auto it = block_ids_.find(key);
  if (it != block_ids_.end()) {
    return it->second;
  }

  if (!writer_ || !writer_->good()) {
    return 0;
  }

  uint64_t block_id = next_block_id_++;
  w1::rewind::block_definition_record record{};
  record.block_id = block_id;
  record.module_id = module_id;
  record.module_offset = module_offset;
  record.size = size;
  if (!writer_->write_block_definition(record)) {
    return 0;
  }

  block_ids_.emplace(std::move(key), block_id);
  return block_id;
}

void rewind_recorder::append_memory_access(
    thread_state& state, w1::trace_context& ctx, const w1::memory_event& event, w1::rewind::memory_access_kind kind
) {
  if (!state.pending.has_value()) {
    return;
  }

  w1::rewind::memory_access_record record{};
  record.sequence = state.pending->record.sequence;
  record.thread_id = state.pending->record.thread_id;
  record.kind = kind;
  record.address = event.address;
  record.size = event.size;

  if (config_.memory.include_values && config_.memory.max_value_bytes > 0) {
    size_t max_bytes = static_cast<size_t>(config_.memory.max_value_bytes);
    size_t capture_size = std::min<size_t>(event.size, max_bytes);
    if (capture_size > 0) {
      if (event.value_valid && capture_size <= sizeof(uint64_t)) {
        record.data.resize(capture_size);
        uint64_t value = event.value;
        for (size_t i = 0; i < capture_size; ++i) {
          record.data[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
        }
        record.value_known = true;
      } else {
        auto bytes = ctx.memory().read_bytes(event.address, capture_size);
        if (bytes.has_value()) {
          record.data = std::move(*bytes);
          record.value_known = true;
        }
      }
      record.value_truncated = event.size > capture_size;
    }
  }

  state.pending->memory_accesses.push_back(std::move(record));
  state.memory_events += 1;
}

} // namespace w1rewind
