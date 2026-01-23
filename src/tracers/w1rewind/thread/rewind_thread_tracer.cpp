#include "rewind_thread_tracer.hpp"

#include <optional>
#include <utility>

#include "thread/memory_access_builder.hpp"
#include "thread/register_delta_builder.hpp"
#include "thread/snapshot_builder.hpp"
#include "thread/stack_window_policy.hpp"

namespace w1rewind {
namespace {

std::optional<w1::util::register_state> capture_registers(const QBDI::GPRState* gpr) {
  if (!gpr) {
    return std::nullopt;
  }
  return w1::util::register_capturer::capture(gpr);
}

w1::instruction_event patch_instruction_event(const w1::instruction_event& event, QBDI::VMInstanceRef vm) {
  w1::instruction_event adjusted = event;
  if ((adjusted.address == 0 || adjusted.size == 0) && vm) {
    if (const auto* analysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION)) {
      adjusted.address = analysis->address;
      adjusted.size = analysis->instSize;
    }
  }
  return adjusted;
}

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

template <rewind_flow Mode, bool CaptureMemory>
rewind_thread_tracer<Mode, CaptureMemory>::rewind_thread_tracer(
    std::shared_ptr<rewind_engine> engine, const rewind_config& config
)
    : engine_(std::move(engine)), config_(config), memory_filter_(config_.memory),
      log_(redlog::get_logger("w1rewind.thread")) {}

template <rewind_flow Mode, bool CaptureMemory>
rewind_thread_tracer<Mode, CaptureMemory>::rewind_thread_tracer(
    std::shared_ptr<rewind_engine> engine, const rewind_config& config, const w1::runtime::thread_info&
)
    : rewind_thread_tracer(std::move(engine), config) {}

template <rewind_flow Mode, bool CaptureMemory>
void rewind_thread_tracer<Mode, CaptureMemory>::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  state_ = thread_state{};
  state_.thread_id = event.thread_id;
  if (event.name && *event.name != '\0') {
    state_.name = event.name;
  } else {
    state_.name = "thread";
  }
}

template <rewind_flow Mode, bool CaptureMemory>
void rewind_thread_tracer<Mode, CaptureMemory>::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;

  if (state_.thread_id == 0) {
    state_.thread_id = event.thread_id;
  }
  if (state_.name.empty() && event.name) {
    state_.name = event.name;
  }
  if (state_.name.empty()) {
    state_.name = "thread";
  }

  if (engine_ && engine_->trace_ready()) {
    engine_->finalize_thread(state_.thread_id, state_.name.empty() ? "thread" : state_.name, state_.pending);
  }

  log_.inf(
      "rewind stats", redlog::field("thread_id", state_.thread_id),
      redlog::field("flow_kind", Mode == rewind_flow::instruction ? "instructions" : "blocks"),
      redlog::field("flow_events", state_.flow_count), redlog::field("snapshots", state_.snapshot_state.snapshot_count),
      redlog::field("memory_events", state_.memory_events)
  );
}

template <rewind_flow Mode, bool CaptureMemory>
void rewind_thread_tracer<Mode, CaptureMemory>::on_basic_block_entry(
    w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) vm;
  (void) state;
  (void) fpr;

  if constexpr (Mode != rewind_flow::block) {
    return;
  }

  if (event.address == 0 || event.size == 0) {
    return;
  }

  if (state_.thread_id == 0) {
    state_.thread_id = event.thread_id;
  }

  std::optional<w1::util::register_state> regs;
  const bool need_regs = should_capture_registers();
  if (need_regs) {
    regs = capture_registers(gpr);
  }

  if (!ensure_trace_ready(ctx, regs)) {
    return;
  }

  if (engine_ && !engine_->begin_thread(state_.thread_id, state_.name)) {
    return;
  }

  const uint32_t flags = apply_arm_thumb_flags(
      regs ? &*regs : nullptr, engine_->arch_spec(), 0, w1::rewind::trace_block_flag_mode_valid,
      w1::rewind::trace_block_flag_thumb
  );

  uint64_t sequence = 0;
  if (!engine_->emit_block(state_.thread_id, event.address, event.size, flags, sequence)) {
    return;
  }

  state_.flow_count += 1;

  if ((config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0) && regs.has_value()) {
    auto snapshot = maybe_capture_snapshot(ctx, *regs, engine_->schema(), config_, state_.snapshot_state, log_);
    if (snapshot.has_value()) {
      engine_->emit_snapshot(
          state_.thread_id, sequence, snapshot->snapshot_id, snapshot->registers, snapshot->stack_segments,
          std::move(snapshot->reason)
      );
    }
  }
}

template <rewind_flow Mode, bool CaptureMemory>
void rewind_thread_tracer<Mode, CaptureMemory>::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) fpr;

  if constexpr (Mode != rewind_flow::instruction) {
    return;
  }

  auto adjusted = patch_instruction_event(event, vm);
  if (adjusted.address == 0) {
    return;
  }
  if (adjusted.size == 0) {
    adjusted.size = 1;
  }

  if (state_.thread_id == 0) {
    state_.thread_id = adjusted.thread_id;
  }

  std::optional<w1::util::register_state> regs;
  const bool need_regs = should_capture_registers() || !engine_ || !engine_->trace_ready();
  if (need_regs) {
    regs = capture_registers(gpr);
  }

  if (!ensure_trace_ready(ctx, regs)) {
    return;
  }

  if (engine_ && !engine_->begin_thread(state_.thread_id, state_.name)) {
    return;
  }

  if (engine_) {
    engine_->flush_pending(state_.pending);
  }

  pending_instruction pending{};
  pending.thread_id = state_.thread_id;
  pending.address = adjusted.address;
  pending.size = adjusted.size;
  pending.flags = apply_arm_thumb_flags(
      regs ? &*regs : nullptr, engine_->arch_spec(), 0, w1::rewind::trace_inst_flag_mode_valid,
      w1::rewind::trace_inst_flag_thumb
  );

  if (config_.registers.deltas && regs.has_value()) {
    pending.register_deltas = capture_register_deltas(engine_->schema(), *regs, state_.last_registers);
  }

  state_.flow_count += 1;
  if ((config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0) && regs.has_value()) {
    auto snapshot = maybe_capture_snapshot(ctx, *regs, engine_->schema(), config_, state_.snapshot_state, log_);
    if (snapshot.has_value()) {
      pending.snapshot = std::move(snapshot);
    }
  }

  state_.pending = std::move(pending);
}

template <rewind_flow Mode, bool CaptureMemory>
void rewind_thread_tracer<Mode, CaptureMemory>::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) vm;
  (void) fpr;

  if constexpr (!CaptureMemory) {
    return;
  }
  if constexpr (Mode != rewind_flow::instruction) {
    return;
  }

  if (config_.memory.access == rewind_config::memory_access::none) {
    return;
  }

  if (!state_.pending.has_value()) {
    return;
  }

  if (event.size == 0) {
    return;
  }

  std::optional<w1::util::register_state> regs;
  if (memory_filter_.uses_stack_window()) {
    regs = capture_registers(gpr);
    if (!regs.has_value()) {
      log_.err("missing register state for stack window filtering");
      return;
    }
  }

  std::vector<stack_window_segment> stack_segments;
  if (memory_filter_.uses_stack_window()) {
    auto window = compute_stack_window_segments(*regs, config_.stack_window);
    if (window.frame_window_missing && !state_.snapshot_state.warned_missing_frame) {
      log_.wrn("frame pointer not available; stack window will use SP-only segments");
      state_.snapshot_state.warned_missing_frame = true;
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
        config_, ctx, event, w1::rewind::memory_access_kind::read, segments, state_.pending->memory_accesses,
        state_.memory_events
    );
  }
  if (event.is_write && capture_writes) {
    append_memory_access(
        config_, ctx, event, w1::rewind::memory_access_kind::write, segments, state_.pending->memory_accesses,
        state_.memory_events
    );
  }
}

template <rewind_flow Mode, bool CaptureMemory>
bool rewind_thread_tracer<Mode, CaptureMemory>::ensure_trace_ready(
    w1::trace_context& ctx, const std::optional<w1::util::register_state>& regs
) {
  if (!engine_) {
    return false;
  }
  if (engine_->trace_ready()) {
    return true;
  }
  if (!regs.has_value()) {
    log_.err("missing register state for trace start");
    return false;
  }
  return engine_->ensure_trace_ready(ctx, *regs);
}

template <rewind_flow Mode, bool CaptureMemory>
bool rewind_thread_tracer<Mode, CaptureMemory>::should_capture_registers() const {
  if (!engine_) {
    return true;
  }
  if (!engine_->trace_ready()) {
    return true;
  }
  if (uses_arm_flags()) {
    return true;
  }
  if (config_.registers.deltas || config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0) {
    return true;
  }
  return false;
}

template <rewind_flow Mode, bool CaptureMemory> bool rewind_thread_tracer<Mode, CaptureMemory>::uses_arm_flags() const {
  if (!engine_) {
    return false;
  }
  return engine_->arch_spec().arch_family == w1::arch::family::arm;
}

template class rewind_thread_tracer<rewind_flow::instruction, true>;
template class rewind_thread_tracer<rewind_flow::instruction, false>;
template class rewind_thread_tracer<rewind_flow::block, false>;

} // namespace w1rewind
