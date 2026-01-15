#include "memory_collector.hpp"

#include <sstream>

namespace w1mem {

memory_collector::memory_collector(const memory_config& config)
    : config_(config), log_(redlog::get_logger("w1mem.collector")) {
  if (!config_.output_path.empty()) {
    w1::io::jsonl_writer_config writer_config;
    writer_config.buffer_size_bytes = config_.buffer_size_bytes;
    writer_config.flush_event_count = config_.flush_event_count;
    writer_config.flush_byte_count = config_.flush_byte_count;

    jsonl_writer_ = std::make_unique<w1::io::jsonl_writer>(config_.output_path, writer_config);
    if (!jsonl_writer_->is_open()) {
      log_.err("failed to open output file", redlog::field("path", config_.output_path));
      jsonl_writer_.reset();
    }
  }
}

void memory_collector::record_instruction() {
  instruction_count_++;
  stats_.total_instructions++;
}

void memory_collector::record_memory_access(
    const w1::runtime::module_registry& modules, uint64_t instruction_addr, uint64_t memory_addr, uint32_t size,
    uint8_t access_type, uint64_t value, bool value_valid
) {
  if (access_type == 1) {
    stats_.total_reads++;
    stats_.total_bytes_read += size;
    if (unique_read_addrs_.insert(memory_addr).second) {
      stats_.unique_read_addresses++;
    }
  } else if (access_type == 2) {
    stats_.total_writes++;
    stats_.total_bytes_written += size;
    if (unique_write_addrs_.insert(memory_addr).second) {
      stats_.unique_write_addresses++;
    }
  }

  memory_access_entry entry{};
  entry.instruction_addr = instruction_addr;
  entry.memory_addr = memory_addr;
  entry.size = size;
  entry.access_type = access_type;
  entry.instruction_count = instruction_count_;
  entry.instruction_module = get_module_name(modules, instruction_addr);
  entry.memory_module = get_module_name(modules, memory_addr);
  entry.value = value;
  entry.value_valid = value_valid;

  if (jsonl_writer_) {
    ensure_metadata_written(modules);
    write_event(entry);
  }
}

void memory_collector::ensure_metadata_written(const w1::runtime::module_registry& modules) {
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

void memory_collector::write_metadata() {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  std::stringstream json;
  json << "{\"type\":\"metadata\",\"version\":1,\"tracer\":\"w1mem\"";
  json << ",\"config\":{\"record_values\":" << (config_.record_values ? "true" : "false") << "}";
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

void memory_collector::write_event(const memory_access_entry& entry) {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  std::stringstream json;
  json << "{\"type\":\"event\",\"data\":{";
  json << "\"instruction_addr\":" << entry.instruction_addr;
  json << ",\"memory_addr\":" << entry.memory_addr;
  json << ",\"size\":" << entry.size;
  json << ",\"access_type\":" << static_cast<uint32_t>(entry.access_type);
  json << ",\"instruction_count\":" << entry.instruction_count;
  json << ",\"instruction_module\":\"" << entry.instruction_module << "\"";
  json << ",\"memory_module\":\"" << entry.memory_module << "\"";
  json << ",\"value\":" << entry.value;
  json << ",\"value_valid\":" << (entry.value_valid ? "true" : "false");
  json << "}}";

  jsonl_writer_->write_line(json.str());
}

std::string memory_collector::get_module_name(const w1::runtime::module_registry& modules, uint64_t address) const {
  if (address == 0) {
    return "null";
  }

  if (auto module = modules.find_containing(address)) {
    return module->name;
  }

  return "unknown";
}

} // namespace w1mem
