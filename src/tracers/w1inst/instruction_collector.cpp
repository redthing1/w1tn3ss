#include "instruction_collector.hpp"
#include <chrono>
#include <sstream>

namespace w1inst {

mnemonic_collector::mnemonic_collector(const std::string& output_file, const std::vector<std::string>& target_mnemonics)
    : instruction_count_(0), matched_count_(0), metadata_written_(false), modules_initialized_(false) {

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
  stats_.target_mnemonics = target_mnemonics;

  // convert vector to set for faster lookup
  for (const auto& mnemonic : target_mnemonics) {
    target_mnemonic_set_.insert(mnemonic);
  }
}

void mnemonic_collector::record_instruction() {
  instruction_count_++;
  stats_.total_instructions++;
}

void mnemonic_collector::record_mnemonic(
    uint64_t address, const std::string& mnemonic, const std::string& disassembly
) {
  // check if this mnemonic matches our targets
  bool matches = false;

  // special case: '*' means match all instructions
  if (target_mnemonic_set_.count("*")) {
    matches = true;
  } else {
    // exact string matching
    matches = (target_mnemonic_set_.find(mnemonic) != target_mnemonic_set_.end());
  }

  if (!matches) {
    return; // not a target mnemonic
  }

  matched_count_++;
  stats_.matched_instructions++;

  // skip if no output configured
  if (!jsonl_writer_) {
    return;
  }

  ensure_metadata_written();

  // create and write event
  mnemonic_entry entry;
  entry.address = address;
  entry.mnemonic = mnemonic;
  entry.disassembly = disassembly;
  entry.instruction_count = instruction_count_;
  entry.module_name = get_module_name(address);

  write_event(entry);
}

void mnemonic_collector::ensure_metadata_written() {
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

void mnemonic_collector::initialize_module_tracking() {
  if (modules_initialized_) {
    return;
  }

  // scan all executable modules
  auto modules = scanner_.scan_executable_modules();

  // rebuild index with all modules for fast lookup
  index_.rebuild_from_modules(std::move(modules));

  modules_initialized_ = true;
}

std::string mnemonic_collector::get_module_name(uint64_t address) const {
  if (address == 0) {
    return "unknown";
  }

  // ensure modules are initialized before lookup
  if (!modules_initialized_) {
    // lazy initialization - cast away const for initialization
    const_cast<mnemonic_collector*>(this)->initialize_module_tracking();
  }

  // fast lookup using module range index
  auto module_info = index_.find_containing(address);
  if (module_info) {
    return module_info->name;
  }

  // fallback for addresses not in any known module
  return "unknown";
}

void mnemonic_collector::write_metadata() {
  if (!jsonl_writer_ || !jsonl_writer_->is_open()) {
    return;
  }

  // create metadata object
  std::stringstream json;
  json << "{\"type\":\"metadata\",\"version\":1,\"tracer\":\"w1inst\"";

  // add target mnemonics
  json << ",\"target_mnemonics\":[";
  bool first = true;
  for (const auto& mnemonic : stats_.target_mnemonics) {
    if (!first) {
      json << ",";
    }
    first = false;
    json << "\"" << mnemonic << "\"";
  }
  json << "]";

  // add module information
  json << ",\"modules\":[";

  first = true;
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

void mnemonic_collector::write_event(const mnemonic_entry& entry) {
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

} // namespace w1inst