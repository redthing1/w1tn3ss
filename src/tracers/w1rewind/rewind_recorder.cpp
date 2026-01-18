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

std::string arch_id_for_trace(w1::rewind::trace_arch arch) {
  switch (arch) {
  case w1::rewind::trace_arch::x86_64:
    return "x86_64";
  case w1::rewind::trace_arch::x86:
    return "x86";
  case w1::rewind::trace_arch::aarch64:
    return "aarch64";
  case w1::rewind::trace_arch::arm:
    return "arm";
  default:
    break;
  }
  return "unknown";
}

std::string gdb_arch_for_trace(w1::rewind::trace_arch arch) {
  switch (arch) {
  case w1::rewind::trace_arch::x86_64:
    return "i386:x86-64";
  case w1::rewind::trace_arch::x86:
    return "i386";
  case w1::rewind::trace_arch::aarch64:
    return "aarch64";
  case w1::rewind::trace_arch::arm:
    return "arm";
  default:
    break;
  }
  return {};
}

std::string gdb_feature_for_trace(w1::rewind::trace_arch arch) {
  switch (arch) {
  case w1::rewind::trace_arch::x86_64:
  case w1::rewind::trace_arch::x86:
    return "org.gnu.gdb.i386.core";
  case w1::rewind::trace_arch::aarch64:
    return "org.gnu.gdb.aarch64.core";
  case w1::rewind::trace_arch::arm:
    return "org.gnu.gdb.arm.core";
  default:
    break;
  }
  return "org.w1tn3ss.rewind";
}

std::string detect_os_id() {
#if defined(_WIN32)
  return "windows";
#elif defined(__APPLE__)
  return "macos";
#elif defined(__linux__)
  return "linux";
#else
  return {};
#endif
}

bool is_pc_name(const std::string& name) {
  return name == "pc" || name == "rip" || name == "eip";
}

bool is_sp_name(const std::string& name) {
  return name == "sp" || name == "rsp" || name == "esp";
}

bool is_flags_name(const std::string& name) {
  return name == "eflags" || name == "rflags" || name == "nzcv" || name == "cpsr";
}

w1::rewind::register_class register_class_for_name(const std::string& name) {
  if (is_flags_name(name)) {
    return w1::rewind::register_class::flags;
  }
  return w1::rewind::register_class::gpr;
}

uint32_t register_bitsize_for_name(w1::rewind::trace_arch arch, const std::string& name, uint32_t pointer_size_bytes) {
  uint32_t pointer_bits = pointer_size_bytes * 8;
  if (arch == w1::rewind::trace_arch::x86_64 || arch == w1::rewind::trace_arch::x86) {
    if (name == "eflags" || name == "rflags") {
      return 32;
    }
    if (name == "fs" || name == "gs") {
      return 16;
    }
  }
  if (arch == w1::rewind::trace_arch::aarch64) {
    if (name == "nzcv") {
      return 32;
    }
  }
  if (arch == w1::rewind::trace_arch::arm) {
    if (name == "cpsr") {
      return 32;
    }
  }
  return pointer_bits;
}

std::string gdb_name_for_register(const std::string& name, w1::rewind::trace_arch arch) {
  if (arch == w1::rewind::trace_arch::aarch64 && name == "nzcv") {
    return "cpsr";
  }
  return name;
}
} // namespace

namespace w1rewind {

rewind_recorder::rewind_recorder(rewind_config config, std::shared_ptr<w1::rewind::trace_writer> writer)
    : config_(std::move(config)), writer_(std::move(writer)), instruction_flow_(config_.requires_instruction_flow()) {
  w1::rewind::trace_builder_config builder_config;
  builder_config.writer = writer_;
  builder_config.log = log_;
  builder_config.options.record_instructions = instruction_flow_;
  builder_config.options.record_register_deltas = config_.record_register_deltas;
  builder_config.options.record_memory_access = config_.memory.enabled;
  builder_config.options.record_memory_values = config_.memory.include_values;
  builder_config.options.record_snapshots = config_.snapshot_interval > 0;
  builder_config.options.record_stack_snapshot = config_.stack_snapshot_bytes > 0;
  builder_ = std::make_unique<w1::rewind::trace_builder>(std::move(builder_config));
}

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

  if (!ensure_builder_ready(ctx, gpr)) {
    return;
  }

  if (!builder_->begin_thread(thread.thread_id, thread.thread_name)) {
    return;
  }

  uint64_t address = event.address;
  uint32_t size = event.size;
  if (address == 0 || size == 0) {
    return;
  }

  auto [module_id, module_offset] = map_instruction_address(ctx.modules(), address);
  uint64_t sequence = 0;
  if (!builder_->emit_block(thread.thread_id, module_id, module_offset, size, sequence)) {
    return;
  }

  thread.flow_count += 1;

  if (config_.snapshot_interval > 0) {
    w1::util::register_state regs = w1::util::register_capturer::capture(gpr);
    auto snapshot = maybe_capture_snapshot(ctx, thread, regs);
    if (snapshot.has_value()) {
      builder_->emit_snapshot(
          thread.thread_id,
          sequence,
          snapshot->snapshot_id,
          snapshot->registers,
          snapshot->stack_snapshot,
          std::move(snapshot->reason)
      );
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

  if (!ensure_builder_ready(ctx, gpr)) {
    return;
  }

  if (!builder_->begin_thread(state.thread_id, state.thread_name)) {
    return;
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
  pending.thread_id = state.thread_id;
  pending.module_id = module_id;
  pending.module_offset = module_offset;
  pending.size = size;
  pending.flags = 0;

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

  if (builder_ready_ && builder_ && builder_->good()) {
    builder_->begin_thread(state.thread_id, state.thread_name);
    builder_->end_thread(state.thread_id);
    builder_->flush();
  }

  log_.inf(
      "rewind stats", redlog::field("thread_id", state.thread_id),
      redlog::field("flow_kind", instruction_flow_ ? "instructions" : "blocks"),
      redlog::field("flow_events", state.flow_count), redlog::field("snapshots", state.snapshot_count),
      redlog::field("memory_events", state.memory_events)
  );
}

bool rewind_recorder::ensure_builder_ready(w1::trace_context& ctx, const QBDI::GPRState* gpr) {
  if (builder_ready_) {
    return true;
  }
  if (!builder_ || !builder_->good()) {
    log_.err("trace builder not ready");
    return false;
  }
  if (!gpr) {
    log_.err("missing gpr state for register specs");
    return false;
  }

  w1::util::register_state regs = w1::util::register_capturer::capture(gpr);
  update_register_table(regs);
  if (register_specs_.empty()) {
    log_.err("register specs missing");
    return false;
  }
  ctx.modules().refresh();
  update_module_table(ctx.modules());

  const auto arch = w1::rewind::detect_trace_arch();
  w1::rewind::target_info_record target{};
  target.arch_id = arch_id_for_trace(arch);
  target.pointer_bits = w1::rewind::detect_pointer_size() * 8;
  target.endianness = w1::rewind::detect_trace_endianness();
  target.os = detect_os_id();
  target.abi.clear();
  target.cpu.clear();
  target.gdb_arch = gdb_arch_for_trace(arch);
  target.gdb_feature = gdb_feature_for_trace(arch);
  if (!builder_->begin_trace(target, register_specs_)) {
    log_.err("failed to begin trace", redlog::field("error", builder_->error()));
    return false;
  }

  if (!module_table_.empty()) {
    if (!builder_->set_module_table(module_table_)) {
      log_.err("failed to write module table", redlog::field("error", builder_->error()));
      return false;
    }
  }

  builder_ready_ = true;
  return true;
}

void rewind_recorder::flush_pending(thread_state& state) {
  if (!state.pending.has_value()) {
    return;
  }

  pending_instruction pending = std::move(*state.pending);
  state.pending.reset();

  if (!builder_ || !builder_->good()) {
    return;
  }

  uint64_t sequence = 0;
  if (instruction_flow_) {
    if (!builder_->emit_instruction(
            pending.thread_id,
            pending.module_id,
            pending.module_offset,
            pending.size,
            pending.flags,
            sequence
        )) {
      return;
    }
  }

  if (config_.record_register_deltas && !pending.register_deltas.empty()) {
    if (!builder_->emit_register_deltas(pending.thread_id, sequence, pending.register_deltas)) {
      return;
    }
  }

  if (config_.memory.enabled) {
    for (const auto& access : pending.memory_accesses) {
      if (!builder_->emit_memory_access(
              pending.thread_id,
              sequence,
              access.kind,
              access.address,
              access.size,
              access.value_known,
              access.value_truncated,
              access.data
          )) {
        return;
      }
    }
  }

  if (pending.snapshot.has_value() && config_.snapshot_interval > 0) {
    builder_->emit_snapshot(
        pending.thread_id,
        sequence,
        pending.snapshot->snapshot_id,
        pending.snapshot->registers,
        pending.snapshot->stack_snapshot,
        std::move(pending.snapshot->reason)
    );
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
  register_specs_.clear();
  register_specs_.reserve(register_table_.size());
  const auto arch = w1::rewind::detect_trace_arch();
  const uint32_t pointer_size = w1::rewind::detect_pointer_size();
  for (size_t i = 0; i < register_table_.size(); ++i) {
    const auto& name = register_table_[i];
    auto reg_id = static_cast<uint16_t>(i);
    register_ids_[name] = reg_id;

    w1::rewind::register_spec spec{};
    spec.reg_id = reg_id;
    spec.name = name;
    spec.bits = static_cast<uint16_t>(register_bitsize_for_name(arch, name, pointer_size));
    spec.flags = 0;
    if (is_pc_name(name)) {
      spec.flags |= w1::rewind::register_flag_pc;
    }
    if (is_sp_name(name)) {
      spec.flags |= w1::rewind::register_flag_sp;
    }
    if (is_flags_name(name)) {
      spec.flags |= w1::rewind::register_flag_flags;
    }
    spec.gdb_name = gdb_name_for_register(name, arch);
    spec.reg_class = register_class_for_name(name);
    spec.value_kind = w1::rewind::register_value_kind::u64;
    register_specs_.push_back(std::move(spec));
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

void rewind_recorder::append_memory_access(
    thread_state& state, w1::trace_context& ctx, const w1::memory_event& event, w1::rewind::memory_access_kind kind
) {
  if (!state.pending.has_value()) {
    return;
  }

  pending_memory_access record{};
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
