#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <redlog.hpp>

#include "w1tn3ss/io/jsonl_writer.hpp"
#include "w1tn3ss/runtime/module_registry.hpp"

#include "instruction_config.hpp"

namespace w1inst {

struct mnemonic_entry {
  uint64_t address = 0;
  std::string mnemonic;
  std::string disassembly;
  std::string module_name;
};

struct mnemonic_stats {
  uint64_t matched_instructions = 0;
  uint64_t unique_sites = 0;
  std::vector<std::string> target_mnemonics;
};

class mnemonic_collector {
public:
  explicit mnemonic_collector(const instruction_config& config);
  ~mnemonic_collector();

  void record_mnemonic(
      const w1::runtime::module_registry& modules, uint64_t address, std::string_view mnemonic,
      std::string_view disassembly
  );

  const mnemonic_stats& get_stats() const { return stats_; }
  void shutdown();

private:
  void ensure_metadata_written(const w1::runtime::module_registry& modules);
  void write_metadata();
  void write_event(const mnemonic_entry& entry);
  std::string get_module_name(const w1::runtime::module_registry& modules, uint64_t address) const;

  instruction_config config_{};
  mnemonic_stats stats_;
  std::unordered_set<uint64_t> unique_addresses_;
  std::unique_ptr<w1::io::jsonl_writer> jsonl_writer_;
  bool metadata_written_ = false;
  bool shutdown_called_ = false;

  std::vector<w1::runtime::module_info> modules_{};
  bool modules_cached_ = false;

  redlog::logger log_ = redlog::get_logger("w1inst.collector");
};

} // namespace w1inst
