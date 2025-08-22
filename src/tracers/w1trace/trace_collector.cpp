#include "trace_collector.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace w1trace {

trace_collector::trace_collector(const std::string& output_file, bool track_control_flow)
    : output_file_(output_file), track_control_flow_(track_control_flow), instruction_count_(0), last_address_(0),
      metadata_written_(false), modules_initialized_(false), log_(redlog::get_logger("w1trace.collector")),
      shutdown_called_(false) {

  // initialize output if file specified
  if (!output_file_.empty()) {
    jsonl_writer_ = std::make_unique<w1::util::jsonl_writer>(output_file);
    if (!jsonl_writer_->is_open()) {
      log_.err("failed to open output file", redlog::field("path", output_file));
      jsonl_writer_.reset();
    }
  }

  // initialize stats
  stats_ = {};

  log_.inf(
      "trace collector initialized", redlog::field("output_file", output_file_),
      redlog::field("track_control_flow", track_control_flow)
  );
}

trace_collector::~trace_collector() {
  if (!shutdown_called_) {
    shutdown();
  }
}

void trace_collector::record_instruction(uint64_t address) {
  // check for control flow if we have a pending branch
  if (track_control_flow_ && pending_branch_) {
    check_control_flow(address);
  }

  // record the instruction
  stats_.total_instructions++;

  insn_event event;
  event.step = instruction_count_;
  event.address = address;

  // write event if output configured
  if (jsonl_writer_) {
    ensure_metadata_written();
    write_insn_event(event);
  }

  instruction_count_++;
  last_address_ = address;
}

void trace_collector::mark_pending_branch(uint64_t address, const std::string& mnemonic) {
  if (!track_control_flow_) {
    return;
  }

  // store pending branch info
  pending_branch_ = pending_branch{address, mnemonic, classify_branch_type(mnemonic)};
}

void trace_collector::check_control_flow(uint64_t current_address) {
  if (!pending_branch_) {
    return;
  }

  // for simplicity, always record a branch event when we have a pending branch
  // the actual destination is the current address we're at now
  branch_event event;
  event.type = pending_branch_->type;
  event.source = pending_branch_->source_address;
  event.dest = current_address;

  // update statistics
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

  // write event if output configured
  if (jsonl_writer_) {
    write_branch_event(event);
  }

  // clear pending branch
  pending_branch_.reset();
}

std::string trace_collector::classify_branch_type(const std::string& mnemonic) const {
  // convert to uppercase for comparison
  std::string upper_mnem = mnemonic;
  std::transform(upper_mnem.begin(), upper_mnem.end(), upper_mnem.begin(), ::toupper);

  // architecture-specific classification
#if defined(QBDI_ARCH_AARCH64) || defined(QBDI_ARCH_ARM)
  if (upper_mnem.find("BL") == 0) {
    return "call"; // branch with link
  } else if (upper_mnem == "RET" || upper_mnem.find("RET") == 0) {
    return "ret";
  } else if (upper_mnem == "B" || upper_mnem == "BR") {
    return "jmp"; // unconditional branch
  } else if (upper_mnem[0] == 'B') {
    return "cond"; // conditional branch (B.EQ, B.NE, etc.)
  }
#elif defined(QBDI_ARCH_X86_64) || defined(QBDI_ARCH_X86)
  if (upper_mnem.find("CALL") == 0) {
    return "call";
  } else if (upper_mnem == "RET" || upper_mnem.find("RET") == 0) {
    return "ret";
  } else if (upper_mnem == "JMP" || upper_mnem.find("JMP") == 0) {
    return "jmp";
  } else if (upper_mnem[0] == 'J') {
    return "cond"; // conditional jumps (JE, JNE, JZ, etc.)
  }
#endif

  return "branch"; // generic fallback
}

void trace_collector::shutdown() {
  if (shutdown_called_) {
    return;
  }

  log_.inf("shutting down trace collector");

  // clear any pending branch
  pending_branch_.reset();

  // close output file
  if (jsonl_writer_) {
    jsonl_writer_.reset();
  }

  log_.inf(
      "trace collector shutdown complete", redlog::field("total_instructions", stats_.total_instructions),
      redlog::field("total_branches", stats_.total_branches)
  );

  shutdown_called_ = true;
}

void trace_collector::initialize_module_tracking() {
  if (modules_initialized_) {
    return;
  }

  // scan all executable modules
  auto modules = scanner_.scan_executable_modules();

  // rebuild index with all modules for fast lookup
  index_.rebuild_from_modules(std::move(modules));

  modules_initialized_ = true;
}

std::string trace_collector::get_module_name(uint64_t address) const {
  if (address == 0) {
    return "null";
  }

  // ensure modules are initialized before lookup
  if (!modules_initialized_) {
    // lazy initialization - cast away const for initialization
    const_cast<trace_collector*>(this)->initialize_module_tracking();
  }

  // fast lookup using module range index
  auto module_info = index_.find_containing(address);
  if (module_info) {
    return module_info->name;
  }

  // fallback for addresses not in any known module
  return "unknown";
}

void trace_collector::ensure_metadata_written() {
  if (!jsonl_writer_ || metadata_written_) {
    return;
  }

  // ensure modules are initialized
  if (!modules_initialized_) {
    initialize_module_tracking();
  }

  write_metadata();
  metadata_written_ = true;
}

void trace_collector::write_metadata() {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  // create metadata object
  std::stringstream json;
  json << "{\"type\":\"metadata\",\"version\":1,\"tracer\":\"w1trace\"";

  // add configuration
  json << ",\"config\":{\"track_control_flow\":" << (track_control_flow_ ? "true" : "false") << "}";

  // add module information
  json << ",\"modules\":[";

  bool first = true;
  size_t module_id = 0;
  index_.visit_all([&](const w1::util::module_info& mod) {
    if (!first) {
      json << ",";
    }
    first = false;

    json << "{\"id\":" << module_id++ << ",\"name\":\"" << mod.name << "\""
         << ",\"path\":\"" << mod.path << "\""
         << ",\"base\":" << mod.base_address << ",\"size\":" << mod.size << ",\"type\":\""
         << (mod.type == w1::util::module_type::MAIN_EXECUTABLE ? "main" : "library") << "\""
         << ",\"is_system\":" << (mod.is_system_library ? "true" : "false") << "}";
  });

  json << "]}";

  jsonl_writer_->write_line(json.str());
}

void trace_collector::write_insn_event(const insn_event& event) {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  // serialize directly as top-level event
  std::stringstream json;
  json << "{\"type\":\"insn\""
       << ",\"step\":" << event.step << ",\"address\":" << event.address << "}";

  jsonl_writer_->write_line(json.str());
}

void trace_collector::write_branch_event(const branch_event& event) {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  // serialize directly as top-level event
  std::stringstream json;
  json << "{\"type\":\"branch\""
       << ",\"branch_type\":\"" << event.type << "\""
       << ",\"source\":" << event.source << ",\"dest\":" << event.dest << "}";

  jsonl_writer_->write_line(json.str());
}

} // namespace w1trace