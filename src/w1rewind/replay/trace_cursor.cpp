#include "trace_cursor.hpp"

#include <redlog.hpp>

namespace w1::rewind {

namespace {

bool record_is_flow(const trace_record& record, bool use_blocks, uint64_t& sequence, uint64_t& thread_id) {
  if (use_blocks && std::holds_alternative<block_exec_record>(record)) {
    const auto& exec = std::get<block_exec_record>(record);
    sequence = exec.sequence;
    thread_id = exec.thread_id;
    return true;
  }
  if (!use_blocks && std::holds_alternative<instruction_record>(record)) {
    const auto& inst = std::get<instruction_record>(record);
    sequence = inst.sequence;
    thread_id = inst.thread_id;
    return true;
  }
  return false;
}

} // namespace

trace_cursor::trace_cursor(trace_cursor_config config)
    : config_(std::move(config)), reader_(config_.trace_path) {}

bool trace_cursor::open() {
  close();
  if (!reader_.open()) {
    error_ = reader_.error();
    return false;
  }
  open_ = true;
  return true;
}

void trace_cursor::close() {
  reader_.close();
  index_.reset();
  pending_.reset();
  pending_location_.reset();
  open_ = false;
  error_.clear();
}

bool trace_cursor::load_index() {
  error_.clear();
  if (!open_) {
    error_ = "trace not open";
    return false;
  }

  std::string index_path = config_.index_path;
  if (index_path.empty()) {
    index_path = default_trace_index_path(config_.trace_path);
  }

  trace_index loaded;
  auto log = redlog::get_logger("w1rewind.trace_cursor");
  if (!load_trace_index(index_path, loaded, log)) {
    error_ = "failed to load trace index";
    return false;
  }

  if (loaded.header.trace_version != reader_.header().version) {
    error_ = "trace index version mismatch";
    return false;
  }
  if (loaded.header.trace_flags != reader_.header().flags) {
    error_ = "trace index flags mismatch";
    return false;
  }
  if (loaded.header.chunk_size != reader_.header().chunk_size) {
    error_ = "trace index chunk size mismatch";
    return false;
  }

  index_ = std::move(loaded);
  return true;
}

bool trace_cursor::seek_flow(uint64_t thread_id, uint64_t sequence) {
  error_.clear();
  pending_.reset();
  pending_location_.reset();

  if (!index_) {
    error_ = "trace index not loaded";
    return false;
  }

  auto anchor = index_->find_anchor(thread_id, sequence);
  if (!anchor.has_value()) {
    error_ = "no anchor for thread";
    return false;
  }

  if (!seek_to_anchor(*anchor)) {
    return false;
  }

  return scan_to_flow(thread_id, sequence);
}

bool trace_cursor::seek_to_location(const trace_record_location& location) {
  error_.clear();
  pending_.reset();
  pending_location_.reset();

  if (!index_) {
    error_ = "trace index not loaded";
    return false;
  }
  if (location.chunk_index >= index_->chunks.size()) {
    error_ = "trace location chunk out of range";
    return false;
  }

  const auto& chunk = index_->chunks[location.chunk_index];
  if (!reader_.seek_to_chunk(chunk, location.chunk_index, location.record_offset)) {
    error_ = reader_.error();
    return false;
  }

  return true;
}

bool trace_cursor::read_next(trace_record& record) {
  return read_next(record, nullptr);
}

bool trace_cursor::read_next(trace_record& record, trace_record_location* location) {
  if (!error_.empty()) {
    return false;
  }

  if (pending_.has_value()) {
    record = std::move(*pending_);
    pending_.reset();
    if (location && pending_location_.has_value()) {
      *location = *pending_location_;
    }
    pending_location_.reset();
    return true;
  }

  if (!reader_.read_next(record, location)) {
    if (!reader_.error().empty()) {
      error_ = reader_.error();
    }
    return false;
  }

  return true;
}

bool trace_cursor::seek_to_anchor(const trace_anchor& anchor) {
  if (!index_) {
    error_ = "trace index not loaded";
    return false;
  }
  if (anchor.chunk_index >= index_->chunks.size()) {
    error_ = "trace anchor chunk out of range";
    return false;
  }

  const auto& chunk = index_->chunks[anchor.chunk_index];
  if (!reader_.seek_to_chunk(chunk, anchor.chunk_index, anchor.record_offset)) {
    error_ = reader_.error();
    return false;
  }

  return true;
}

bool trace_cursor::scan_to_flow(uint64_t thread_id, uint64_t sequence) {
  bool use_blocks = (reader_.header().flags & trace_flag_blocks) != 0;
  bool use_instructions = (reader_.header().flags & trace_flag_instructions) != 0;

  if (!use_blocks && !use_instructions) {
    error_ = "trace has no flow records";
    return false;
  }
  if (use_blocks && use_instructions) {
    error_ = "trace has multiple flow record kinds";
    return false;
  }

  trace_record record;
  trace_record_location location{};
  while (reader_.read_next(record, &location)) {
    uint64_t record_sequence = 0;
    uint64_t record_thread = 0;
    if (!record_is_flow(record, use_blocks, record_sequence, record_thread)) {
      continue;
    }
    if (record_thread != thread_id) {
      continue;
    }
    if (record_sequence < sequence) {
      continue;
    }
    if (record_sequence != sequence) {
      error_ = "flow sequence not found";
      return false;
    }
    pending_ = std::move(record);
    pending_location_ = location;
    return true;
  }

  if (!reader_.error().empty()) {
    error_ = reader_.error();
    return false;
  }

  error_ = "flow sequence not found";
  return false;
}

} // namespace w1::rewind
