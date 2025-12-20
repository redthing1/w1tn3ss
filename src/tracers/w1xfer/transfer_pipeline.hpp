#pragma once

#include <memory>
#include <unordered_set>

#include <QBDI.h>

#include <w1tn3ss/abi/api_dispatcher.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/symbols/symbol_lookup.hpp>

#include "transfer_config.hpp"
#include "transfer_types.hpp"
#include "transfer_writer_jsonl.hpp"

namespace w1xfer {

class transfer_pipeline {
public:
  explicit transfer_pipeline(const transfer_config& config);

  void initialize_modules();

  void record_call(
      uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  void record_return(
      uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  const transfer_stats& stats() const { return stats_; }

private:
  transfer_config config_;
  transfer_stats stats_{};
  uint64_t instruction_index_ = 0;
  bool modules_initialized_ = false;

  w1::util::module_scanner scanner_;
  w1::util::module_range_index module_index_;
  w1::symbols::symbol_lookup symbol_lookup_;
  std::unique_ptr<w1::abi::api_dispatcher> api_dispatcher_;
  std::unique_ptr<transfer_writer_jsonl> writer_;

  std::unordered_set<uint64_t> unique_call_targets_;
  std::unordered_set<uint64_t> unique_return_sources_;

  void update_call_depth(transfer_type type);
  void ensure_modules_initialized();
  void maybe_write_record(const transfer_record& record);
  void record_transfer(
      transfer_type type, uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm,
      const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  std::optional<transfer_endpoint> build_endpoint(uint64_t address) const;
  std::optional<transfer_api_info> analyze_api_event(
      transfer_type type, uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm,
      const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
      const std::optional<transfer_endpoint>& source,
      const std::optional<transfer_endpoint>& target
  );
};

} // namespace w1xfer
