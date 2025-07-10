#include "memory_collector.hpp"
#include <chrono>
#include <sstream>

namespace w1mem {

memory_collector::memory_collector(const std::string& output_file)
    : instruction_count_(0), metadata_written_(false), modules_initialized_(false) {

  // initialize output if file specified
  if (!output_file.empty()) {
    jsonl_writer_ = std::make_unique<w1::util::jsonl_writer>(output_file);
    if (!jsonl_writer_->is_open()) {
      log_.err("failed to open output file", redlog::field("path", output_file));
      jsonl_writer_.reset();
    }
  }

  // initialize stats
  stats_ = {};
}

void memory_collector::record_instruction() {
  instruction_count_++;
  stats_.total_instructions++;
}

void memory_collector::record_memory_access(
    uint64_t instruction_addr, uint64_t memory_addr, uint32_t size, uint8_t access_type
) {
  // update statistics
  if (access_type == 1) { // read
    stats_.total_reads++;
    stats_.total_bytes_read += size;
    unique_read_addrs_.insert(memory_addr);
    stats_.unique_read_addresses = unique_read_addrs_.size();
  } else if (access_type == 2) { // write
    stats_.total_writes++;
    stats_.total_bytes_written += size;
    unique_write_addrs_.insert(memory_addr);
    stats_.unique_write_addresses = unique_write_addrs_.size();
  }

  // create event
  memory_access_entry entry;
  entry.instruction_addr = instruction_addr;
  entry.memory_addr = memory_addr;
  entry.size = size;
  entry.access_type = access_type;
  entry.instruction_count = instruction_count_;
  entry.instruction_module = get_module_name(instruction_addr);
  entry.memory_module = get_module_name(memory_addr);

  // write event if output configured
  if (jsonl_writer_) {
    ensure_metadata_written();
    write_event(entry);
  }
}

void memory_collector::ensure_metadata_written() {
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

void memory_collector::initialize_module_tracking() {
  if (modules_initialized_) {
    return;
  }

  // scan all executable modules
  auto modules = scanner_.scan_executable_modules();

  // rebuild index with all modules for fast lookup
  index_.rebuild_from_modules(std::move(modules));

  modules_initialized_ = true;
}

std::string memory_collector::get_module_name(uint64_t address) const {
  if (address == 0) {
    return "null";
  }

  // ensure modules are initialized before lookup
  if (!modules_initialized_) {
    // lazy initialization - cast away const for initialization
    const_cast<memory_collector*>(this)->initialize_module_tracking();
  }

  // fast lookup using module range index
  auto module_info = index_.find_containing(address);
  if (module_info) {
    return module_info->name;
  }

  // fallback for addresses not in any known module
  return "unknown";
}

void memory_collector::write_metadata() {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  // create metadata object
  std::stringstream json;
  json << "{\"type\":\"metadata\",\"version\":1,\"tracer\":\"w1mem\"";

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

void memory_collector::write_event(const memory_access_entry& entry) {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  // serialize the entry to json with compact formatting
  std::string json = JS::serializeStruct(entry, JS::SerializerOptions(JS::SerializerOptions::Compact));

  // wrap in event envelope
  std::stringstream wrapped;
  wrapped << "{\"type\":\"event\",\"data\":" << json << "}";

  jsonl_writer_->write_line(wrapped.str());
}

} // namespace w1mem