#include "rewind_thread_tracer.hpp"

#include <algorithm>
#include <cctype>
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

  if (!ensure_trace_ready(regs)) {
    return;
  }

  if (engine_ && !engine_->begin_thread(state_.thread_id, state_.name)) {
    return;
  }

  const uint32_t space_id = 0;
  const uint16_t mode_id = engine_->resolve_mode_id(regs ? &*regs : nullptr);

  uint64_t sequence = 0;
  if (!engine_->emit_block(state_.thread_id, event.address, event.size, space_id, mode_id, sequence)) {
    return;
  }

  state_.flow_count += 1;

  if ((config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0) && regs.has_value()) {
    auto snapshot = maybe_capture_snapshot(
        ctx, *regs, engine_->schema(), config_, state_.snapshot_state, log_, engine_->byte_order()
    );
    if (snapshot.has_value()) {
      engine_->emit_snapshot(
          state_.thread_id, sequence, snapshot->snapshot_id, snapshot->registers, snapshot->memory_segments
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

  if (!ensure_trace_ready(regs)) {
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
  pending.space_id = 0;
  pending.mode_id = engine_->resolve_mode_id(regs ? &*regs : nullptr);

  bool capture_regs = config_.registers.deltas || config_.registers.bytes;
  if (capture_regs && regs.has_value()) {
    pending.register_writes =
        capture_register_deltas(engine_->schema(), *regs, engine_->byte_order(), state_.last_registers);
  }

  state_.flow_count += 1;
  if ((config_.registers.snapshot_interval > 0 || config_.stack_snapshots.interval > 0) && regs.has_value()) {
    auto snapshot = maybe_capture_snapshot(
        ctx, *regs, engine_->schema(), config_, state_.snapshot_state, log_, engine_->byte_order()
    );
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
    auto window = compute_stack_window_segments(*regs, engine_->schema(), config_.stack_window);
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
        config_, ctx, event, w1::rewind::mem_access_op::read, segments, state_.pending->memory_accesses,
        state_.memory_events, 0
    );
  }
  if (event.is_write && capture_writes) {
    append_memory_access(
        config_, ctx, event, w1::rewind::mem_access_op::write, segments, state_.pending->memory_accesses,
        state_.memory_events, 0
    );
  }
}

template <rewind_flow Mode, bool CaptureMemory>
bool rewind_thread_tracer<Mode, CaptureMemory>::ensure_trace_ready(
    const std::optional<w1::util::register_state>& regs
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
  return engine_->ensure_trace_ready(*regs);
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
  if (config_.registers.deltas || config_.registers.bytes || config_.registers.snapshot_interval > 0 ||
      config_.stack_snapshots.interval > 0) {
    return true;
  }
  return false;
}

template <rewind_flow Mode, bool CaptureMemory> bool rewind_thread_tracer<Mode, CaptureMemory>::uses_arm_flags() const {
  if (!engine_) {
    return false;
  }
  const auto& arch = engine_->arch_descriptor();
  std::string id = arch.arch_id;
  std::string gdb = arch.gdb_arch;
  std::transform(id.begin(), id.end(), id.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  std::transform(gdb.begin(), gdb.end(), gdb.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  if (id.find("arm") != std::string::npos || id == "thumb") {
    return true;
  }
  if (gdb.find("arm") != std::string::npos) {
    return true;
  }
  return false;
}

template class rewind_thread_tracer<rewind_flow::instruction, true>;
template class rewind_thread_tracer<rewind_flow::instruction, false>;
template class rewind_thread_tracer<rewind_flow::block, false>;

} // namespace w1rewind
