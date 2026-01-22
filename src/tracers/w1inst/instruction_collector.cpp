#include "instruction_collector.hpp"

#include <sstream>

namespace w1inst {

mnemonic_collector::mnemonic_collector(const instruction_config& config)
    : config_(config), log_(redlog::get_logger("w1inst.collector")) {
  if (!config_.output_file.empty()) {
    w1::io::jsonl_writer_config writer_config;
    writer_config.buffer_size_bytes = config_.buffer_size_bytes;
    writer_config.flush_event_count = config_.flush_event_count;
    writer_config.flush_byte_count = config_.flush_byte_count;

    jsonl_writer_ = std::make_unique<w1::io::jsonl_writer>(config_.output_file, writer_config);
    if (!jsonl_writer_->is_open()) {
      log_.err("failed to open output file", redlog::field("path", config_.output_file));
      jsonl_writer_.reset();
    }
  }

  stats_.target_mnemonics = config_.mnemonic_list;
  log_.inf(
      "instruction collector initialized", redlog::field("output_file", config_.output_file),
      redlog::field("target_count", stats_.target_mnemonics.size())
  );
}

mnemonic_collector::~mnemonic_collector() {
  if (!shutdown_called_) {
    shutdown();
  }
}

void mnemonic_collector::record_mnemonic(
    const w1::runtime::module_catalog& modules, uint64_t address, std::string_view mnemonic,
    std::string_view disassembly
) {
  stats_.matched_instructions++;
  unique_addresses_.insert(address);
  stats_.unique_sites = unique_addresses_.size();

  mnemonic_entry entry{};
  entry.address = address;
  entry.mnemonic = std::string(mnemonic);
  entry.disassembly = std::string(disassembly);
  entry.module_name = get_module_name(modules, address);

  if (jsonl_writer_) {
    ensure_metadata_written(modules);
    write_event(entry);
  }
}

void mnemonic_collector::shutdown() {
  if (shutdown_called_) {
    return;
  }

  log_.inf(
      "instruction collector shutdown", redlog::field("matched", stats_.matched_instructions),
      redlog::field("unique_sites", stats_.unique_sites)
  );

  if (jsonl_writer_) {
    jsonl_writer_.reset();
  }

  shutdown_called_ = true;
}

void mnemonic_collector::ensure_metadata_written(const w1::runtime::module_catalog& modules) {
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

std::string mnemonic_collector::get_module_name(const w1::runtime::module_catalog& modules, uint64_t address) const {
  if (address == 0) {
    return "unknown";
  }

  if (auto module = modules.find_containing(address)) {
    return module->name;
  }

  return "unknown";
}

void mnemonic_collector::write_metadata() {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  std::stringstream json;
  json << "{\"type\":\"metadata\",\"version\":1,\"tracer\":\"w1inst\"";
  json << ",\"config\":{\"target_mnemonics\":[";

  bool first = true;
  for (const auto& mnemonic : stats_.target_mnemonics) {
    if (!first) {
      json << ",";
    }
    first = false;
    json << "\"" << mnemonic << "\"";
  }

  json << "]}";
  json << ",\"modules\":[";

  first = true;
  size_t module_id = 0;
  for (const auto& module : modules_) {
    if (!first) {
      json << ",";
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

void mnemonic_collector::write_event(const mnemonic_entry& entry) {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  std::stringstream json;
  json << "{\"type\":\"event\",\"data\":{";
  json << "\"address\":" << entry.address;
  json << ",\"mnemonic\":\"" << entry.mnemonic << "\"";
  json << ",\"disassembly\":\"" << entry.disassembly << "\"";
  json << ",\"module\":\"" << entry.module_name << "\"";
  json << "}}";

  jsonl_writer_->write_line(json.str());
}

} // namespace w1inst
