#include "recording_engine.hpp"

#include <algorithm>

#include "stack_window_policy.hpp"
#include "target_environment_provider.hpp"
#include "w1runtime/register_capture.hpp"

namespace w1rewind {

namespace {

uint32_t apply_arm_thumb_flags(
    const w1::util::register_state* regs, const w1::arch::arch_spec& arch, uint32_t flags, uint32_t valid_flag,
    uint32_t thumb_flag
) {
  if (!regs) {
    return flags;
  }
  if (arch.arch_family != w1::arch::family::arm) {
    return flags;
  }
  if (arch.arch_mode != w1::arch::mode::arm && arch.arch_mode != w1::arch::mode::thumb) {
    return flags;
  }

  uint64_t cpsr = 0;
  if (!regs->get_register("cpsr", cpsr)) {
    return flags;
  }
  flags |= valid_flag;
  if (((cpsr >> 5) & 1U) != 0) {
    flags |= thumb_flag;
  }
  return flags;
}

} // namespace

recording_engine::recording_engine(rewind_config config, std::shared_ptr<w1::rewind::trace_record_sink> sink)
    : config_(std::move(config)), sink_(std::move(sink)),
      instruction_flow_(config_.flow.mode == rewind_config::flow_options::mode::instruction),
      memory_filter_(config_.memory) {
  w1::rewind::trace_builder_config builder_config;
  builder_config.sink = sink_;
  builder_config.log = log_;
  builder_config.options.record_instructions = instruction_flow_;
  builder_config.options.record_register_deltas = config_.registers.deltas;
  builder_config.options.record_memory_access = config_.memory.access != rewind_config::memory_access::none;
  builder_config.options.record_memory_values = config_.memory.values;
  builder_config.options.record_snapshots = config_.registers.snapshot_interval > 0;
  builder_config.options.record_stack_segments = config_.stack_snapshots.interval > 0;
  builder_ = std::make_unique<w1::rewind::trace_builder>(std::move(builder_config));
  emitter_ = std::make_unique<trace_emitter>(builder_.get(), config_, instruction_flow_);
}

void recording_engine::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  auto& state = threads_[event.thread_id];
  state.thread_id = event.thread_id;
  if (event.name) {
    state.thread_name = event.name;
  }
}

void recording_engine::on_basic_block_entry(
    w1::trace_context& ctx, const w1::basic_block_event& event, const w1::util::register_state* regs
) {
  if (instruction_flow_) {
    return;
  }

  auto& thread = threads_[event.thread_id];
  if (thread.thread_id == 0) {
    thread.thread_id = event.thread_id;
  }

  if (!ensure_builder_ready(ctx, regs)) {
    return;
  }

  if (!build_thread_start(thread)) {
    return;
  }

  uint64_t address = event.address;
  uint32_t size = event.size;
  if (address == 0 || size == 0) {
    return;
  }

  uint32_t flags = resolve_block_flags(regs);

  uint64_t sequence = 0;
  if (!emitter_ || !emitter_->emit_block(thread.thread_id, address, size, flags, sequence)) {
    return;
  }

  thread.flow_count += 1;

  if (config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0) {
    const w1::util::register_state empty_regs;
    const auto* use_regs = regs ? regs : &empty_regs;
    auto snapshot = maybe_capture_snapshot(ctx, *use_regs, register_schema_, config_, thread.snapshot_state, log_);
    if (snapshot.has_value()) {
      builder_->emit_snapshot(
          thread.thread_id, sequence, snapshot->snapshot_id, snapshot->registers, snapshot->stack_segments,
          std::move(snapshot->reason)
      );
    }
  }
}

void recording_engine::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, const w1::util::register_state* regs
) {
  if (!instruction_flow_) {
    return;
  }

  auto& state = threads_[event.thread_id];
  if (state.thread_id == 0) {
    state.thread_id = event.thread_id;
  }

  if (!ensure_builder_ready(ctx, regs)) {
    return;
  }

  if (!build_thread_start(state)) {
    return;
  }

  if (emitter_) {
    emitter_->flush_pending(state.pending);
  }

  pending_instruction pending{};
  pending.thread_id = state.thread_id;
  pending.address = event.address;
  pending.size = event.size;
  pending.flags = resolve_instruction_flags(regs);

  bool need_registers =
      config_.registers.deltas || config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0;
  w1::util::register_state empty_regs;
  const auto* use_regs = regs ? regs : &empty_regs;

  if (need_registers) {
    if (config_.registers.deltas) {
      pending.register_deltas = capture_register_deltas(register_schema_, *use_regs, state.last_registers);
    }
  }

  state.flow_count += 1;
  if (config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0) {
    auto snapshot = maybe_capture_snapshot(ctx, *use_regs, register_schema_, config_, state.snapshot_state, log_);
    if (snapshot.has_value()) {
      pending.snapshot = std::move(snapshot);
    }
  }

  state.pending = std::move(pending);
}

void recording_engine::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, const w1::util::register_state* regs
) {
  if (!instruction_flow_ || config_.memory.access == rewind_config::memory_access::none) {
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

  std::vector<stack_window_segment> stack_segments;
  if (memory_filter_.uses_stack_window()) {
    if (!regs) {
      log_.err("missing register state for stack window filtering");
      return;
    }
    auto window = compute_stack_window_segments(*regs, config_.stack_window);
    if (window.frame_window_missing && !state.snapshot_state.warned_missing_frame) {
      log_.wrn("frame pointer not available; stack window will use SP-only segments");
      state.snapshot_state.warned_missing_frame = true;
    }
    stack_segments = std::move(window.segments);
  }

  auto segments = memory_filter_.filter(event.address, event.size, stack_segments);
  if (segments.empty()) {
    return;
  }

  bool capture_reads = config_.memory.access == rewind_config::memory_access::reads ||
                       config_.memory.access == rewind_config::memory_access::reads_writes;
  bool capture_writes = config_.memory.access == rewind_config::memory_access::writes ||
                        config_.memory.access == rewind_config::memory_access::reads_writes;

  if (event.is_read && capture_reads) {
    append_memory_access(
        config_, ctx, event, w1::rewind::memory_access_kind::read, segments, state.pending->memory_accesses,
        state.memory_events
    );
  }
  if (event.is_write && capture_writes) {
    append_memory_access(
        config_, ctx, event, w1::rewind::memory_access_kind::write, segments, state.pending->memory_accesses,
        state.memory_events
    );
  }
}

void recording_engine::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  auto it = threads_.find(event.thread_id);
  if (it == threads_.end()) {
    return;
  }

  auto& state = it->second;
  if (emitter_) {
    emitter_->flush_pending(state.pending);
    emitter_->finalize_thread(state.thread_id, state.thread_name);
  }

  log_.inf(
      "rewind stats", redlog::field("thread_id", state.thread_id),
      redlog::field("flow_kind", instruction_flow_ ? "instructions" : "blocks"),
      redlog::field("flow_events", state.flow_count), redlog::field("snapshots", state.snapshot_state.snapshot_count),
      redlog::field("memory_events", state.memory_events)
  );
}

bool recording_engine::ensure_builder_ready(w1::trace_context& ctx, const w1::util::register_state* regs) {
  if (builder_ready_) {
    return true;
  }
  if (!builder_ || !builder_->good()) {
    log_.err("trace builder not ready");
    return false;
  }
  if (!regs) {
    log_.err("missing register state for register specs");
    return false;
  }

  arch_spec_ = w1::arch::detect_host_arch_spec();
  if (arch_spec_.arch_family == w1::arch::family::unknown || arch_spec_.arch_mode == w1::arch::mode::unknown) {
    log_.err("unsupported host architecture");
    return false;
  }

  register_schema_.update(*regs, arch_spec_);
  if (register_schema_.empty()) {
    log_.err("register specs missing");
    return false;
  }
  ctx.modules().refresh();
  update_module_table(ctx.modules());

  auto memory_map = collect_memory_map(module_table_);

  w1::rewind::target_info_record target{};
  target.os = detect_os_id();
  target.abi.clear();
  target.cpu.clear();
  auto environment = build_target_environment(memory_map, module_table_, arch_spec_);
  if (!builder_->begin_trace(arch_spec_, target, environment, register_schema_.specs())) {
    log_.err("failed to begin trace", redlog::field("error", builder_->error()));
    return false;
  }

  if (!module_table_.empty()) {
    if (!builder_->set_module_table(module_table_)) {
      log_.err("failed to write module table", redlog::field("error", builder_->error()));
      return false;
    }
  }

  if (!memory_map.empty()) {
    if (!builder_->set_memory_map(std::move(memory_map))) {
      log_.err("failed to write memory map", redlog::field("error", builder_->error()));
      return false;
    }
  }

  builder_ready_ = true;
  return true;
}

void recording_engine::update_module_table(const w1::runtime::module_registry& modules) {
  module_table_ = build_module_table(modules, arch_spec_);
}

uint32_t recording_engine::resolve_block_flags(const w1::util::register_state* regs) const {
  return apply_arm_thumb_flags(
      regs, arch_spec_, 0, w1::rewind::trace_block_flag_mode_valid, w1::rewind::trace_block_flag_thumb
  );
}

uint32_t recording_engine::resolve_instruction_flags(const w1::util::register_state* regs) const {
  return apply_arm_thumb_flags(
      regs, arch_spec_, 0, w1::rewind::trace_inst_flag_mode_valid, w1::rewind::trace_inst_flag_thumb
  );
}

bool recording_engine::build_thread_start(thread_state& state) {
  if (!emitter_) {
    return false;
  }
  return emitter_->begin_thread(state.thread_id, state.thread_name);
}

} // namespace w1rewind
