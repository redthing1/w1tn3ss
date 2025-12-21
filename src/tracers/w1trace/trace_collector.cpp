#include "trace_collector.hpp"

#include <sstream>

namespace w1trace {

trace_collector::trace_collector(const trace_config& config)
    : output_file_(config.output_file), track_control_flow_(config.track_control_flow),
      log_(redlog::get_logger("w1trace.collector")) {
  if (!output_file_.empty()) {
    w1::io::jsonl_writer_config writer_config;
    writer_config.buffer_size_bytes = config.buffer_size_bytes;
    writer_config.flush_event_count = config.flush_event_count;
    writer_config.flush_byte_count = config.flush_byte_count;

    jsonl_writer_ = std::make_unique<w1::io::jsonl_writer>(output_file_, writer_config);
    if (!jsonl_writer_->is_open()) {
      log_.err("failed to open output file", redlog::field("path", output_file_));
      jsonl_writer_.reset();
    }
  }

  log_.inf(
      "trace collector initialized", redlog::field("output_file", output_file_),
      redlog::field("track_control_flow", track_control_flow_)
  );
}

trace_collector::~trace_collector() {
  if (!shutdown_called_) {
    shutdown();
  }
}

void trace_collector::record_instruction(const w1::runtime::module_registry& modules, uint64_t address) {
  stats_.total_instructions++;

  insn_event event{};
  event.step = instruction_count_;
  event.address = address;

  if (jsonl_writer_) {
    ensure_metadata_written(modules);
    write_insn_event(event);
  }

  instruction_count_++;
}

void trace_collector::record_branch(const branch_event& event) {
  if (!track_control_flow_) {
    return;
  }

  stats_.total_branches++;
  if (event.type == "call") {
    stats_.total_calls++;
  } else if (event.type == "ret") {
    stats_.total_returns++;
  } else if (event.type == "jmp") {
    stats_.total_jumps++;
  } else if (event.type == "cond") {
    stats_.total_conditional++;
  }

  if (jsonl_writer_) {
    write_branch_event(event);
  }
}

void trace_collector::shutdown() {
  if (shutdown_called_) {
    return;
  }

  log_.inf("shutting down trace collector");

  if (jsonl_writer_) {
    jsonl_writer_.reset();
  }

  log_.inf(
      "trace collector shutdown complete", redlog::field("total_instructions", stats_.total_instructions),
      redlog::field("total_branches", stats_.total_branches)
  );

  shutdown_called_ = true;
}

void trace_collector::ensure_metadata_written(const w1::runtime::module_registry& modules) {
  if (metadata_written_) {
    return;
  }

  if (!modules_cached_) {
    modules_ = modules.list_modules();
    modules_cached_ = true;
  }

  write_metadata();
  metadata_written_ = true;
}

void trace_collector::write_metadata() {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  std::stringstream json;
  json << "{\"type\":\"metadata\",\"version\":1,\"tracer\":\"w1trace\"";
  json << ",\"config\":{\"track_control_flow\":" << (track_control_flow_ ? "true" : "false") << "}";
  json << ",\"modules\":[";

  bool first = true;
  size_t module_id = 0;
  for (const auto& module : modules_) {
    if (!first) {
      json << ',';
    }
    first = false;

    json << "{\"id\":" << module_id++ << ",\"name\":\"" << module.name << "\""
         << ",\"path\":\"" << module.path << "\""
         << ",\"base\":" << module.base_address << ",\"size\":" << module.size
         << ",\"is_system\":" << (module.is_system ? "true" : "false") << "}";
  }

  json << "]}";
  jsonl_writer_->write_line(json.str());
}

void trace_collector::write_insn_event(const insn_event& event) {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  std::stringstream json;
  json << "{\"type\":\"insn\",\"step\":" << event.step << ",\"address\":" << event.address << "}";
  jsonl_writer_->write_line(json.str());
}

void trace_collector::write_branch_event(const branch_event& event) {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  std::stringstream json;
  json << "{\"type\":\"branch\",\"branch_type\":\"" << event.type << "\""
       << ",\"source\":" << event.source << ",\"dest\":" << event.dest << "}";
  jsonl_writer_->write_line(json.str());
}

} // namespace w1trace
