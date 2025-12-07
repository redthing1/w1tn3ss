#include "rewind_tracer.hpp"

#include <algorithm>
#include <unordered_map>
#include <utility>
#include <vector>

#include <w1tn3ss/util/register_capture.hpp>

namespace w1rewind {

rewind_tracer::rewind_tracer(
    rewind_config config, w1::rewind::trace_sink_ptr sink, w1::rewind::trace_validator_ptr validator, uint64_t thread_id,
    std::string thread_name, redlog::logger log
)
    : config_(std::move(config)),
      sink_(std::move(sink)),
      validator_(std::move(validator)),
      thread_id_(thread_id),
      thread_name_(std::move(thread_name)),
      log_(std::move(log)) {}

bool rewind_tracer::initialize(QBDI::VM& vm) {
  vm_ = &vm;

  if (!sink_ || !sink_->good()) {
    log_.err("trace sink unavailable", redlog::field("thread_id", thread_id_));
    return false;
  }

  if (config_.record_memory) {
    memory_recording_enabled_ = vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    if (!memory_recording_enabled_) {
      log_.wrn("recordMemoryAccess failed; memory deltas disabled", redlog::field("thread_id", thread_id_));
    }
  }

  if (config_.capture_memory_reads) {
    log_.dbg("memory read capture enabled", redlog::field("thread_id", thread_id_));
  }

  instruction_callback_id_ = vm.addCodeCB(QBDI::POSTINST, on_instruction, this);
  if (instruction_callback_id_ == QBDI::INVALID_EVENTID) {
    log_.err("failed to register instruction callback", redlog::field("thread_id", thread_id_));
    vm_ = nullptr;
    return false;
  }

  sequence_ = 0;
  instruction_count_ = 0;
  boundary_counter_ = 0;
  instructions_since_boundary_ = 0;
  have_last_register_state_ = false;
  last_register_state_ = {};
  stop_requested_ = false;
  validation_failed_ = false;

  log_.dbg(
      "rewind tracer initialized", redlog::field("thread_id", thread_id_), redlog::field("thread", thread_name_),
      redlog::field("record_memory", memory_recording_enabled_)
  );
  return true;
}

void rewind_tracer::shutdown() {
  if (vm_ && instruction_callback_id_ != QBDI::INVALID_EVENTID) {
    vm_->deleteInstrumentation(instruction_callback_id_);
  }

  instruction_callback_id_ = QBDI::INVALID_EVENTID;
  vm_ = nullptr;
  memory_recording_enabled_ = false;
  have_last_register_state_ = false;
  last_register_state_ = {};
  boundary_counter_ = 0;
  instructions_since_boundary_ = 0;
}

QBDI::VMAction rewind_tracer::on_instruction(QBDI::VMInstanceRef, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) {
  auto* tracer = static_cast<rewind_tracer*>(data);
  if (!tracer) {
    return QBDI::CONTINUE;
  }

  return tracer->handle_instruction(gpr, fpr);
}

QBDI::VMAction rewind_tracer::handle_instruction(QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
  (void)fpr;

  if (stop_requested_) {
    return QBDI::CONTINUE;
  }

  if (!config_.record_instructions || !sink_ || !sink_->good() || vm_ == nullptr) {
    return QBDI::CONTINUE;
  }

  w1::rewind::trace_event event;
  event.thread_id = thread_id_;
  event.sequence = sequence_++;

  const QBDI::InstAnalysis* analysis = vm_->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
  if (analysis != nullptr) {
    event.address = analysis->address;
    event.size = analysis->instSize;
  }

  if (config_.record_registers) {
    capture_register_deltas(gpr, event);
  }

  if (config_.record_memory) {
    capture_memory_accesses(event);
  }

  instruction_count_++;
  log_progress();

  if (config_.verbose >= 3 && (!event.registers.empty() || !event.reads.empty() || !event.writes.empty())) {
    log_.dbg(
        "instruction deltas", redlog::field("thread_id", thread_id_), redlog::field("seq", event.sequence),
        redlog::field("address", "0x%llx", static_cast<unsigned long long>(event.address)),
        redlog::field("regs", event.registers.size()), redlog::field("reads", event.reads.size()),
        redlog::field("writes", event.writes.size())
    );
  }

  if (validator_) {
    const auto verdict = validator_->verify(event);
    if (verdict == w1::rewind::trace_validator::result::abort) {
      if (!validation_failed_) {
        log_.err(
            "validation abort", redlog::field("thread_id", thread_id_), redlog::field("sequence", event.sequence)
        );
      }
      validation_failed_ = true;
      stop_requested_ = true;
      return QBDI::CONTINUE;
    } else if (verdict == w1::rewind::trace_validator::result::mismatch_logged) {
      validation_failed_ = true;
    }
  }

  if (!sink_->write_event(event)) {
    log_.err("failed to write instruction event", redlog::field("thread_id", thread_id_));
  }

  instructions_since_boundary_ += 1;
  maybe_emit_boundary_event(gpr, event.address, event.size);

  return QBDI::CONTINUE;
}

void rewind_tracer::capture_register_deltas(const QBDI::GPRState* gpr, w1::rewind::trace_event& event) {
  if (!gpr) {
    return;
  }

  auto current_state = w1::util::register_capturer::capture(gpr);
  const auto& current_map = current_state.get_register_map();

  static const std::unordered_map<std::string, uint64_t> empty_registers;
  const auto& last_map = have_last_register_state_ ? last_register_state_.get_register_map() : empty_registers;

  std::vector<std::pair<std::string, uint64_t>> deltas;
  for (const auto& entry : current_map) {
    const auto it = have_last_register_state_ ? last_map.find(entry.first) : last_map.end();
    if (!have_last_register_state_ || it == last_map.end() || it->second != entry.second) {
      deltas.emplace_back(entry.first, entry.second);
    }
  }

  std::sort(deltas.begin(), deltas.end(), [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });
  for (const auto& delta : deltas) {
    event.registers.push_back(w1::rewind::trace_register_delta{delta.first, delta.second});
  }

  last_register_state_ = std::move(current_state);
  have_last_register_state_ = true;
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

  last_register_state_ = std::move(state);
  have_last_register_state_ = true;
}

void rewind_tracer::capture_memory_accesses(w1::rewind::trace_event& event) {
  if (!memory_recording_enabled_ || vm_ == nullptr) {
    return;
  }

  const std::vector<QBDI::MemoryAccess> accesses = vm_->getInstMemoryAccess();

  for (const auto& access : accesses) {
    const bool is_write = (access.type & QBDI::MEMORY_WRITE) != 0;
    const bool is_read = (access.type & QBDI::MEMORY_READ) != 0;

    if (access.size == 0 || (!is_write && !(is_read && config_.capture_memory_reads))) {
      continue;
    }

    auto build_delta = [&](bool capture_value) {
      w1::rewind::trace_memory_delta delta;
      delta.address = access.accessAddress;
      delta.size = access.size;
      delta.value_known = capture_value && (access.flags & QBDI::MEMORY_UNKNOWN_VALUE) == 0
                          && access.size <= sizeof(access.value);

      if (delta.value_known) {
        delta.data.resize(access.size);
        QBDI::rword value = access.value;
        for (uint16_t i = 0; i < access.size; ++i) {
          delta.data[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
        }
      }

      return delta;
    };

    if (is_read && config_.capture_memory_reads) {
      // todo: capture full buffer for reads larger than pointer size using targeted snapshots
      event.reads.push_back(build_delta(/*capture_value=*/true));
    }

    if (is_write) {
      // todo: for raw syscalls or larger memory writes, capture full buffers via targeted reads
      event.writes.push_back(build_delta(/*capture_value=*/true));
    }
  }
}

void rewind_tracer::maybe_emit_boundary_event(const QBDI::GPRState* gpr, uint64_t address, uint32_t size) {
  if (config_.frame_instruction_interval == 0) {
    return;
  }

  if (instructions_since_boundary_ < config_.frame_instruction_interval) {
    return;
  }

  instructions_since_boundary_ = 0;
  emit_boundary_event(gpr, address, size);
}

void rewind_tracer::emit_boundary_event(const QBDI::GPRState* gpr, uint64_t address, uint32_t size) {
  if (!sink_ || !sink_->good()) {
    return;
  }

  w1::rewind::trace_event event;
  event.type = w1::rewind::trace_event_type::boundary;
  event.thread_id = thread_id_;
  event.sequence = sequence_++;
  event.address = address;
  event.size = size;

  capture_full_registers(gpr, event);

  w1::rewind::trace_event::trace_boundary_info info{};
  info.boundary_id = boundary_counter_++;
  info.flags = w1::rewind::trace_boundary_flag_full_register_snapshot;
  info.reason = "interval";
  event.boundary = info;

  if (config_.verbose >= 3) {
    log_.dbg(
        "emitting boundary event", redlog::field("thread_id", thread_id_),
        redlog::field("boundary_id", static_cast<unsigned long long>(info.boundary_id)),
        redlog::field("sequence", event.sequence)
    );
  }

  if (validator_) {
    const auto verdict = validator_->verify(event);
    if (verdict == w1::rewind::trace_validator::result::abort) {
      if (!validation_failed_) {
        log_.err(
            "validation abort on boundary", redlog::field("thread_id", thread_id_),
            redlog::field("sequence", event.sequence)
        );
      }
      validation_failed_ = true;
      stop_requested_ = true;
      return;
    } else if (verdict == w1::rewind::trace_validator::result::mismatch_logged) {
      validation_failed_ = true;
    }
  }

  if (!sink_->write_event(event)) {
    log_.err("failed to write boundary event", redlog::field("thread_id", thread_id_));
  }
}

void rewind_tracer::log_progress() {
  if (config_.verbose < 3) {
    return;
  }

  if ((instruction_count_ % 50000) == 0) {
    log_.dbg(
        "instruction milestone", redlog::field("thread_id", thread_id_), redlog::field("count", instruction_count_)
    );
  }
}

} // namespace w1rewind
