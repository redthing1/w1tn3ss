#include "snapshot_builder.hpp"

#include "register_delta_builder.hpp"
#include "stack_window_policy.hpp"
#include "w1runtime/memory_reader.hpp"

namespace w1rewind {

namespace {

std::vector<w1::rewind::memory_segment> capture_stack_segments(
    w1::trace_context& ctx, const w1::util::register_state& regs, const register_schema& schema,
    const rewind_config& config, snapshot_state& state, redlog::logger log
) {
  std::vector<w1::rewind::memory_segment> out;
  if (config.stack_snapshots.interval == 0 ||
      config.stack_window.mode == rewind_config::stack_window_options::window_mode::none) {
    return out;
  }
  if (regs.get_register_map().empty()) {
    return out;
  }

  auto window = compute_stack_window_segments(regs, schema, config.stack_window);
  if (window.frame_window_missing && !state.warned_missing_frame) {
    log.wrn("frame pointer not available; stack snapshot will use SP-only segments");
    state.warned_missing_frame = true;
  }

  out.reserve(window.segments.size());
  for (const auto& segment : window.segments) {
    if (segment.size == 0) {
      continue;
    }
    auto bytes = ctx.memory().read_bytes(segment.base, static_cast<size_t>(segment.size));
    if (!bytes.has_value()) {
      continue;
    }
    w1::rewind::memory_segment record{};
    record.space_id = 0;
    record.base = segment.base;
    record.bytes = std::move(*bytes);
    out.push_back(std::move(record));
  }

  return out;
}

} // namespace

std::optional<pending_snapshot> maybe_capture_snapshot(
    w1::trace_context& ctx, const w1::util::register_state& regs, const register_schema& schema,
    const rewind_config& config, snapshot_state& state, redlog::logger log, w1::rewind::endian byte_order
) {
  bool want_register_snapshot = config.registers.snapshot_interval > 0;
  bool want_stack_snapshot = config.stack_snapshots.interval > 0;

  bool register_due = false;
  bool stack_due = false;

  if (want_register_snapshot) {
    state.flow_since_register_snapshot += 1;
    if (state.flow_since_register_snapshot >= config.registers.snapshot_interval) {
      state.flow_since_register_snapshot = 0;
      register_due = true;
    }
  }

  if (want_stack_snapshot) {
    state.flow_since_stack_snapshot += 1;
    if (state.flow_since_stack_snapshot >= config.stack_snapshots.interval) {
      state.flow_since_stack_snapshot = 0;
      stack_due = true;
    }
  }

  if (!register_due && !stack_due) {
    return std::nullopt;
  }

  pending_snapshot snapshot{};
  snapshot.snapshot_id = state.snapshot_count++;
  if (register_due) {
    snapshot.registers = capture_register_snapshot(schema, regs, byte_order);
  }
  if (stack_due) {
    snapshot.memory_segments = capture_stack_segments(ctx, regs, schema, config, state, log);
  }
  snapshot.reason = "interval";
  return snapshot;
}

} // namespace w1rewind
