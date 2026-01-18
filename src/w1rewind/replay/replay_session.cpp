#include "replay_session.hpp"

#include <filesystem>

#include <redlog.hpp>

#include "trace_index.hpp"

namespace w1::rewind {

namespace {

std::string resolve_index_path(const std::string& trace_path, const std::string& index_path) {
  if (!index_path.empty()) {
    return index_path;
  }
  return default_trace_index_path(trace_path);
}

std::string resolve_checkpoint_path(const std::string& trace_path, const std::string& checkpoint_path) {
  if (!checkpoint_path.empty()) {
    return checkpoint_path;
  }
  return default_replay_checkpoint_path(trace_path);
}

std::vector<std::optional<uint64_t>> build_unknown_registers(size_t count) {
  return std::vector<std::optional<uint64_t>>(count, std::nullopt);
}

std::vector<std::optional<uint8_t>> build_unknown_memory(size_t count) {
  return std::vector<std::optional<uint8_t>>(count, std::nullopt);
}

bool is_index_error(const std::string& error) {
  return error.find("trace index") != std::string::npos;
}

replay_session::replay_error_kind map_flow_error_kind(replay_flow_error_kind kind) {
  switch (kind) {
  case replay_flow_error_kind::begin_of_trace:
    return replay_session::replay_error_kind::begin_of_trace;
  case replay_flow_error_kind::end_of_trace:
    return replay_session::replay_error_kind::end_of_trace;
  case replay_flow_error_kind::none:
    return replay_session::replay_error_kind::none;
  default:
    return replay_session::replay_error_kind::other;
  }
}

} // namespace

replay_session::replay_session(replay_session_config config) : config_(std::move(config)) {
  block_decoder_ = config_.block_decoder;
}

bool replay_session::open() {
  close();
  clear_error();

  if (config_.trace_path.empty()) {
    set_error("trace path required");
    return false;
  }

  if (!load_context()) {
    return false;
  }

  if (!ensure_index()) {
    return false;
  }

  if (!ensure_checkpoint()) {
    return false;
  }

  if (!ensure_flow_cursor()) {
    return false;
  }

  open_ = true;

  if (config_.thread_id != 0) {
    if (!select_thread(config_.thread_id, config_.start_sequence)) {
      return false;
    }
  }

  return true;
}

void replay_session::close() {
  flow_cursor_.reset();
  instruction_cursor_.reset();
  context_ = replay_context{};
  breakpoints_.clear();
  current_step_ = flow_step{};
  active_thread_id_ = 0;
  resolved_index_path_.clear();
  checkpoint_index_.reset();
  resolved_checkpoint_path_.clear();
  notice_.reset();
  open_ = false;
  has_position_ = false;
  clear_error();
}

bool replay_session::select_thread(uint64_t thread_id, uint64_t sequence) {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!flow_cursor_.has_value()) {
    set_error("flow cursor not ready");
    return false;
  }

  bool used_checkpoint = false;
  if (checkpoint_index_.has_value() && (config_.track_registers || config_.track_memory)) {
    const auto* checkpoint = find_checkpoint(thread_id, sequence);
    if (checkpoint) {
      if (!flow_cursor_->seek_with_checkpoint(*checkpoint, sequence)) {
        set_error(map_flow_error_kind(flow_cursor_->error_kind()), flow_cursor_->error());
        return false;
      }
      used_checkpoint = true;
    }
  }
  if (!used_checkpoint) {
    if (!flow_cursor_->seek(thread_id, sequence)) {
      set_error(map_flow_error_kind(flow_cursor_->error_kind()), flow_cursor_->error());
      return false;
    }
  }

  active_thread_id_ = thread_id;
  reset_instruction_cursor();
  has_position_ = false;
  current_step_ = flow_step{};
  return true;
}

bool replay_session::step_flow() {
  flow_step step{};
  if (!step_flow_internal(step)) {
    return false;
  }

  reset_instruction_cursor();
  if (instruction_cursor_.has_value()) {
    instruction_cursor_->sync_with_flow_step(step);
  }
  current_step_ = step;
  has_position_ = true;
  return true;
}

bool replay_session::step_backward() {
  reset_instruction_cursor();

  flow_step step{};
  if (!step_flow_backward_internal(step)) {
    return false;
  }

  if (instruction_cursor_.has_value()) {
    instruction_cursor_->sync_with_flow_step(step);
  }
  current_step_ = step;
  has_position_ = true;
  return true;
}

bool replay_session::step_instruction() {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!instruction_cursor_.has_value()) {
    set_error("instruction cursor not ready");
    return false;
  }

  flow_step step{};
  if (!instruction_cursor_->step_forward(step)) {
    auto kind = replay_error_kind::other;
    if (flow_cursor_.has_value()) {
      auto mapped = map_flow_error_kind(flow_cursor_->error_kind());
      kind = mapped == replay_error_kind::none ? replay_error_kind::other : mapped;
    }
    set_error(kind, instruction_cursor_->error());
    return false;
  }

  if (auto notice = instruction_cursor_->take_notice(); notice.has_value()) {
    notice_ = notice;
  }

  current_step_ = step;
  has_position_ = true;
  return true;
}

bool replay_session::step_instruction_backward() {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!instruction_cursor_.has_value()) {
    set_error("instruction cursor not ready");
    return false;
  }
  if (!has_position_) {
    set_error("no current position");
    return false;
  }

  flow_step step{};
  if (!instruction_cursor_->step_backward(step)) {
    auto kind = replay_error_kind::other;
    if (flow_cursor_.has_value()) {
      auto mapped = map_flow_error_kind(flow_cursor_->error_kind());
      kind = mapped == replay_error_kind::none ? replay_error_kind::other : mapped;
    }
    set_error(kind, instruction_cursor_->error());
    return false;
  }

  if (auto notice = instruction_cursor_->take_notice(); notice.has_value()) {
    notice_ = notice;
  }

  current_step_ = step;
  has_position_ = true;
  return true;
}

bool replay_session::continue_until_break() {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }

  for (;;) {
    if (!step_flow()) {
      return false;
    }
    if (is_breakpoint_hit()) {
      return true;
    }
  }
}

void replay_session::add_breakpoint(uint64_t address) { breakpoints_.insert(address); }

void replay_session::remove_breakpoint(uint64_t address) { breakpoints_.erase(address); }

void replay_session::clear_breakpoints() { breakpoints_.clear(); }

std::vector<std::optional<uint64_t>> replay_session::read_registers() const {
  if (!flow_cursor_.has_value()) {
    return build_unknown_registers(context_.register_names.size());
  }
  const replay_state* state = flow_cursor_->state();
  if (!state) {
    return build_unknown_registers(context_.register_names.size());
  }

  const auto& regs = state->registers();
  if (regs.size() == context_.register_names.size()) {
    return regs;
  }

  auto out = build_unknown_registers(context_.register_names.size());
  size_t copy_count = std::min(out.size(), regs.size());
  for (size_t i = 0; i < copy_count; ++i) {
    out[i] = regs[i];
  }
  return out;
}

std::vector<std::optional<uint8_t>> replay_session::read_memory(uint64_t address, size_t size) const {
  if (!flow_cursor_.has_value()) {
    return build_unknown_memory(size);
  }
  const replay_state* state = flow_cursor_->state();
  if (!state) {
    return build_unknown_memory(size);
  }
  return state->read_memory(address, size);
}

const replay_state* replay_session::state() const {
  if (!flow_cursor_.has_value()) {
    return nullptr;
  }
  return flow_cursor_->state();
}

bool replay_session::ensure_index() {
  resolved_index_path_ = resolve_index_path(config_.trace_path, config_.index_path);

  bool index_exists = std::filesystem::exists(resolved_index_path_);
  bool should_build = !index_exists;
  if (index_exists && config_.auto_build_index) {
    std::error_code trace_error;
    std::error_code index_error;
    auto trace_time = std::filesystem::last_write_time(config_.trace_path, trace_error);
    auto index_time = std::filesystem::last_write_time(resolved_index_path_, index_error);
    if (!trace_error && !index_error && trace_time > index_time) {
      should_build = true;
    }
  }

  if (!should_build) {
    return true;
  }

  if (!config_.auto_build_index) {
    set_error(index_exists ? "trace index stale" : "trace index missing");
    return false;
  }

  trace_index_options options;
  trace_index built;
  if (!build_trace_index(config_.trace_path, resolved_index_path_, options, &built, redlog::logger{})) {
    set_error(index_exists ? "failed to rebuild trace index" : "failed to build trace index");
    return false;
  }

  return true;
}

bool replay_session::ensure_checkpoint() {
  if (config_.checkpoint_path.empty() && !config_.auto_build_checkpoint) {
    return true;
  }

  resolved_checkpoint_path_ = resolve_checkpoint_path(config_.trace_path, config_.checkpoint_path);

  if (std::filesystem::exists(resolved_checkpoint_path_)) {
    replay_checkpoint_index loaded;
    std::string error;
    if (!load_replay_checkpoint(resolved_checkpoint_path_, loaded, error)) {
      set_error(error.empty() ? "failed to load checkpoint" : error);
      return false;
    }
    if (!validate_checkpoint(loaded)) {
      return false;
    }
    checkpoint_index_ = std::move(loaded);
    return true;
  }

  if (!config_.auto_build_checkpoint) {
    set_error("checkpoint file missing");
    return false;
  }

  replay_checkpoint_config cfg{};
  cfg.trace_path = config_.trace_path;
  cfg.output_path = resolved_checkpoint_path_;
  cfg.stride = config_.checkpoint_stride;
  cfg.include_memory = config_.checkpoint_include_memory;

  replay_checkpoint_index built;
  std::string error;
  if (!build_replay_checkpoint(cfg, &built, error)) {
    set_error(error.empty() ? "failed to build checkpoint" : error);
    return false;
  }
  if (!validate_checkpoint(built)) {
    return false;
  }

  checkpoint_index_ = std::move(built);
  return true;
}

bool replay_session::validate_checkpoint(const replay_checkpoint_index& index) {
  if (index.header.trace_version != context_.header.version) {
    set_error("checkpoint trace version mismatch");
    return false;
  }
  if (index.header.trace_flags != context_.header.flags) {
    set_error("checkpoint trace flags mismatch");
    return false;
  }
  if (index.header.architecture != context_.header.architecture) {
    set_error("checkpoint architecture mismatch");
    return false;
  }
  if (index.header.pointer_size != context_.header.pointer_size) {
    set_error("checkpoint pointer size mismatch");
    return false;
  }
  if (!context_.register_names.empty() && index.header.register_count != context_.register_names.size()) {
    set_error("checkpoint register count mismatch");
    return false;
  }
  return true;
}

const replay_checkpoint_entry* replay_session::find_checkpoint(uint64_t thread_id, uint64_t sequence) const {
  if (!checkpoint_index_.has_value()) {
    return nullptr;
  }
  return checkpoint_index_->find_checkpoint(thread_id, sequence);
}

std::optional<replay_notice> replay_session::take_notice() {
  if (!notice_.has_value()) {
    return std::nullopt;
  }
  auto out = *notice_;
  notice_.reset();
  return out;
}

void replay_session::reset_instruction_cursor() {
  if (instruction_cursor_.has_value()) {
    instruction_cursor_->reset();
  }
  notice_.reset();
}

bool replay_session::load_context() {
  context_ = replay_context{};

  std::string error;
  if (!load_replay_context(config_.trace_path, context_, error)) {
    set_error(error);
    return false;
  }

  if (config_.context_hook) {
    config_.context_hook(context_);
  }

  if ((config_.track_registers || config_.track_memory) && context_.register_names.empty()) {
    set_error("register table missing");
    return false;
  }

  return true;
}

bool replay_session::ensure_flow_cursor() {
  replay_flow_cursor_config cursor_config{};
  cursor_config.trace_path = config_.trace_path;
  cursor_config.index_path = resolved_index_path_;
  cursor_config.history_size = config_.history_size;
  cursor_config.track_registers = config_.track_registers;
  cursor_config.track_memory = config_.track_memory;
  cursor_config.context = &context_;

  flow_cursor_.emplace(cursor_config);
  if (!flow_cursor_->open()) {
    if (!config_.auto_build_index || !is_index_error(flow_cursor_->error())) {
      set_error(map_flow_error_kind(flow_cursor_->error_kind()), flow_cursor_->error());
      return false;
    }

    trace_index_options options;
    trace_index rebuilt;
    if (!build_trace_index(config_.trace_path, resolved_index_path_, options, &rebuilt, redlog::logger{})) {
      set_error("failed to rebuild trace index");
      return false;
    }

    if (!flow_cursor_->open()) {
      set_error(map_flow_error_kind(flow_cursor_->error_kind()), flow_cursor_->error());
      return false;
    }
  }

  instruction_cursor_.emplace(*flow_cursor_);
  instruction_cursor_->set_decoder(block_decoder_);
  return true;
}

bool replay_session::step_flow_internal(flow_step& out) {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!flow_cursor_.has_value()) {
    set_error("flow cursor not ready");
    return false;
  }

  flow_step step{};
  if (!flow_cursor_->step_forward(step)) {
    set_error(map_flow_error_kind(flow_cursor_->error_kind()), flow_cursor_->error());
    return false;
  }

  out = step;
  return true;
}

bool replay_session::step_flow_backward_internal(flow_step& out) {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!flow_cursor_.has_value()) {
    set_error("flow cursor not ready");
    return false;
  }
  if (!has_position_) {
    set_error("no current position");
    return false;
  }

  if ((config_.track_registers || config_.track_memory) && checkpoint_index_.has_value()) {
    if (current_step_.sequence == 0) {
      set_error(replay_error_kind::begin_of_trace, "at start of trace");
      return false;
    }
    uint64_t target = current_step_.sequence - 1;
    const auto* checkpoint = find_checkpoint(active_thread_id_, target);
    if (checkpoint) {
      if (!flow_cursor_->seek_with_checkpoint(*checkpoint, target)) {
        set_error(map_flow_error_kind(flow_cursor_->error_kind()), flow_cursor_->error());
        return false;
      }
      flow_step step{};
      if (!flow_cursor_->step_forward(step)) {
        set_error(map_flow_error_kind(flow_cursor_->error_kind()), flow_cursor_->error());
        return false;
      }
      out = step;
      return true;
    }
  }

  flow_step step{};
  if (!flow_cursor_->step_backward(step)) {
    set_error(map_flow_error_kind(flow_cursor_->error_kind()), flow_cursor_->error());
    return false;
  }

  out = step;
  return true;
}

bool replay_session::is_breakpoint_hit() const {
  if (!has_position_) {
    return false;
  }
  if (breakpoints_.empty()) {
    return false;
  }
  return breakpoints_.find(current_step_.address) != breakpoints_.end();
}

void replay_session::clear_error() {
  error_.clear();
  error_kind_ = replay_error_kind::none;
}

void replay_session::set_error(const std::string& message) { set_error(replay_error_kind::other, message); }

void replay_session::set_error(replay_error_kind kind, const std::string& message) {
  error_ = message;
  error_kind_ = kind;
}

} // namespace w1::rewind
