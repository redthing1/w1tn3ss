#pragma once

#include <vector>
#include <unordered_set>
#include <cstdint>
#include <string>
#include <memory>
#include <w1common/ext/jsonstruct.hpp>
#include <w1tn3ss/util/jsonl_writer.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <redlog.hpp>

namespace w1inst {

struct mnemonic_entry {
  uint64_t address;
  std::string mnemonic;
  std::string disassembly;
  std::string module_name;

  JS_OBJECT(JS_MEMBER(address), JS_MEMBER(mnemonic), JS_MEMBER(disassembly), JS_MEMBER(module_name));
};

struct mnemonic_stats {
  uint64_t matched_instructions;
  uint64_t unique_sites;
  std::vector<std::string> target_mnemonics;

  JS_OBJECT(JS_MEMBER(matched_instructions), JS_MEMBER(unique_sites), JS_MEMBER(target_mnemonics));
};

class mnemonic_collector {
public:
  explicit mnemonic_collector(const std::string& output_file, const std::vector<std::string>& target_mnemonics);

  void record_mnemonic(uint64_t address, const std::string& mnemonic, const std::string& disassembly);

  const mnemonic_stats& get_stats() const { return stats_; }

private:
  mnemonic_stats stats_;
  std::unordered_set<std::string> target_mnemonic_set_;
  std::unordered_set<uint64_t> unique_addresses_;

  uint64_t matched_count_;

  // jsonl output
  std::unique_ptr<w1::util::jsonl_writer> jsonl_writer_;
  bool metadata_written_;

  // module tracking
  w1::util::module_scanner scanner_;
  w1::util::module_range_index index_;
  bool modules_initialized_;

  redlog::logger log_ = redlog::get_logger("w1.inst.collector");

  void ensure_metadata_written();
  void write_metadata();
  void write_event(const mnemonic_entry& entry);
  void initialize_module_tracking();
  std::string get_module_name(uint64_t address) const;
};

} // namespace w1inst