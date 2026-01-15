#include "rewind_tracer.hpp"

#include <algorithm>
#include <unordered_map>
#include <utility>

namespace w1rewind {

rewind_tracer::rewind_tracer(
    rewind_config config, w1::rewind::trace_sink_ptr sink, w1::rewind::trace_validator_ptr validator
)
    : config_(std::move(config)), sink_(std::move(sink)), validator_(std::move(validator)) {}

void rewind_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  if (initialized_) {
    return;
  }

  thread_id_ = event.thread_id;
  thread_name_ = event.name ? event.name : "thread";

  reset_state();

  if (!ensure_sink_ready()) {
    return;
  }

  if (config_.capture_memory_reads) {
    log_.dbg("memory read capture enabled", redlog::field("thread_id", thread_id_));
  }

  log_.dbg(
      "rewind tracer initialized", redlog::field("thread_id", thread_id_), redlog::field("thread", thread_name_),
      redlog::field("record_memory", config_.record_memory ? "true" : "false")
  );
  initialized_ = true;
}

void rewind_tracer::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) ctx;
  (void) fpr;
  if (!initialized_ || state_.stop_requested || !config_.record_instructions) {
    return;
  }

  if (!ensure_sink_ready()) {
    return;
  }

  flush_pending_event();
  if (state_.stop_requested) {
    return;
  }

  w1::rewind::trace_event next{};
  next.type = w1::rewind::trace_event_type::instruction;
  next.thread_id = event.thread_id;
  next.sequence = state_.sequence++;

  uint64_t address = event.address;
  uint32_t size = event.size;
  if ((address == 0 || size == 0) && vm) {
    if (const auto* analysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION)) {
      address = analysis->address;
      size = analysis->instSize;
    }
  }

  next.address = address;
  next.size = size;

  if (config_.record_registers) {
    capture_register_deltas(gpr, next);
  }

  state_.pending_instruction = std::move(next);
  state_.instruction_count += 1;
  state_.instructions_since_boundary += 1;
  schedule_boundary_if_needed(address, size, gpr);
  log_progress();
}

void rewind_tracer::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) ctx;
  (void) vm;
  (void) gpr;
  (void) fpr;
  if (!initialized_ || state_.stop_requested || !config_.record_memory) {
    return;
  }

  if (!state_.pending_instruction.has_value()) {
    return;
  }

  if (event.size == 0) {
    return;
  }

  if (event.is_read) {
    if (config_.capture_memory_reads) {
      append_memory_delta(event, state_.pending_instruction->reads);
    }
  }

  if (event.is_write) {
    append_memory_delta(event, state_.pending_instruction->writes);
  }
}

void rewind_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  if (!initialized_) {
    return;
  }

  flush_pending_event();
  if (sink_ && sink_->good()) {
    sink_->flush();
  }

  log_.inf(
      "rewind stats", redlog::field("thread_id", thread_id_),
      redlog::field("instructions", state_.instruction_count), redlog::field("boundaries", state_.boundary_counter)
  );

  if (validator_) {
    validator_->finalize();
    const auto& stats = validator_->stats();
    log_.inf(
        "validation summary", redlog::field("checked", stats.events_checked),
        redlog::field("mismatches", stats.mismatches), redlog::field("aborted", stats.aborted)
    );
  }
}

void rewind_tracer::reset_state() {
  state_ = tracer_state{};
}

void rewind_tracer::flush_pending_event() {
  if (!state_.pending_instruction.has_value()) {
    return;
  }

  w1::rewind::trace_event event = std::move(*state_.pending_instruction);
  state_.pending_instruction.reset();

  if (state_.stop_requested) {
    state_.pending_boundary.reset();
    return;
  }

  if (!emit_event(event)) {
    state_.pending_boundary.reset();
    return;
  }

  if (state_.pending_boundary.has_value()) {
    emit_event(*state_.pending_boundary);
    state_.pending_boundary.reset();
  }
}

void rewind_tracer::schedule_boundary_if_needed(uint64_t address, uint32_t size, const QBDI::GPRState* gpr) {
  if (config_.frame_instruction_interval == 0) {
    return;
  }

  if (state_.instructions_since_boundary < config_.frame_instruction_interval) {
    return;
  }

  state_.instructions_since_boundary = 0;

  w1::rewind::trace_event boundary{};
  boundary.type = w1::rewind::trace_event_type::boundary;
  boundary.thread_id = thread_id_;
  boundary.sequence = state_.sequence++;
  boundary.address = address;
  boundary.size = size;

  capture_full_registers(gpr, boundary);

  w1::rewind::trace_event::trace_boundary_info info{};
  info.boundary_id = state_.boundary_counter++;
  info.flags = w1::rewind::trace_boundary_flag_full_register_snapshot;
  info.reason = "interval";
  boundary.boundary = info;

  state_.pending_boundary = std::move(boundary);
}

bool rewind_tracer::emit_event(const w1::rewind::trace_event& event) {
  if (!ensure_sink_ready()) {
    return false;
  }

  if (validator_) {
    const auto verdict = validator_->verify(event);
    if (verdict == w1::rewind::trace_validator::result::abort) {
      if (!state_.validation_failed) {
        const char* kind = (event.type == w1::rewind::trace_event_type::boundary) ? "boundary" : "instruction";
        log_.err(
            "validation abort", redlog::field("thread_id", thread_id_), redlog::field("sequence", event.sequence),
            redlog::field("type", kind)
        );
      }
      state_.validation_failed = true;
      state_.stop_requested = true;
      return false;
    }
    if (verdict == w1::rewind::trace_validator::result::mismatch_logged) {
      state_.validation_failed = true;
    }
  }

  if (!sink_->write_event(event)) {
    log_.err("failed to write trace event", redlog::field("thread_id", thread_id_));
    state_.stop_requested = true;
    return false;
  }

  return true;
}

bool rewind_tracer::ensure_sink_ready() {
  if (!sink_ || !sink_->good()) {
    log_.err("trace sink unavailable", redlog::field("thread_id", thread_id_));
    state_.stop_requested = true;
    return false;
  }
  return true;
}

void rewind_tracer::capture_register_deltas(const QBDI::GPRState* gpr, w1::rewind::trace_event& event) {
  if (!gpr) {
    return;
  }

  auto current_state = w1::util::register_capturer::capture(gpr);
  const auto& current_map = current_state.get_register_map();
  const auto* last_map = state_.last_register_state ? &state_.last_register_state->get_register_map() : nullptr;

  std::vector<std::pair<std::string, uint64_t>> deltas;
  for (const auto& entry : current_map) {
    if (!last_map) {
      deltas.emplace_back(entry.first, entry.second);
      continue;
    }
    const auto it = last_map->find(entry.first);
    if (it == last_map->end() || it->second != entry.second) {
      deltas.emplace_back(entry.first, entry.second);
    }
  }

  std::sort(deltas.begin(), deltas.end(), [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });
  for (const auto& delta : deltas) {
    event.registers.push_back(w1::rewind::trace_register_delta{delta.first, delta.second});
  }

  state_.last_register_state = std::move(current_state);
}

void rewind_tracer::capture_full_registers(const QBDI::GPRState* gpr, w1::rewind::trace_event& event) {
  if (!gpr) {
    return;
  }

  auto state = w1::util::register_capturer::capture(gpr);
  for (const auto& name : state.get_register_names()) {
    uint64_t value = 0;
    if (state.get_register(name, value)) {
      event.registers.push_back(w1::rewind::trace_register_delta{name, value});
    }
  }

  state_.last_register_state = std::move(state);
}

void rewind_tracer::append_memory_delta(
    const w1::memory_event& event, std::vector<w1::rewind::trace_memory_delta>& out
) {
  w1::rewind::trace_memory_delta delta;
  delta.address = event.address;
  delta.size = event.size;
  delta.value_known = event.value_valid && event.size <= sizeof(event.value);

  if (delta.value_known && delta.size > 0) {
    delta.data.resize(delta.size);
    uint64_t value = event.value;
    for (uint16_t i = 0; i < delta.size; ++i) {
      delta.data[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
  }

  out.push_back(std::move(delta));
}

void rewind_tracer::log_progress() {
  if (config_.verbose < 3) {
    return;
  }

  if ((state_.instruction_count % 50000) == 0) {
    log_.dbg(
        "instruction milestone", redlog::field("thread_id", thread_id_),
        redlog::field("count", state_.instruction_count)
    );
  }
}

} // namespace w1rewind
