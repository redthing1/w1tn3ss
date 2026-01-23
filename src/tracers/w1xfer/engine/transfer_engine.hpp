#pragma once

#include <memory>
#include <optional>
#include <unordered_set>

#include <QBDI.h>

#include "w1analysis/abi_dispatcher.hpp"
#include "w1analysis/symbol_lookup.hpp"
#include "w1instrument/tracer/types.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1runtime/module_catalog.hpp"
#include "w1runtime/memory_reader.hpp"
#include "w1runtime/register_capture.hpp"
#include "w1runtime/stack_capture.hpp"

#include "config/transfer_config.hpp"
#include "io/transfer_writer_jsonl.hpp"
#include "model/transfer_types.hpp"

namespace w1xfer {

class transfer_engine {
public:
  explicit transfer_engine(transfer_config config);

  void configure(w1::runtime::module_catalog& modules);
  void attach(const w1::trace_context& ctx);

  void shutdown();
  bool export_output();

  void record_call(
      const w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  void record_return(
      const w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  std::optional<transfer_endpoint> resolve_endpoint(uint64_t address) const;

  const transfer_stats& stats() const { return stats_; }

private:
  void update_call_depth(transfer_type type);
  void record_transfer(
      transfer_type type, const w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void write_record(const transfer_record& record);

  std::optional<transfer_endpoint> build_endpoint(uint64_t address) const;
  std::optional<transfer_api_info> analyze_api_event(
      transfer_type type, const w1::trace_context& ctx, uint64_t source_addr, uint64_t target_addr, QBDI::GPRState* gpr
  );

  size_t default_argument_count() const;

  transfer_config config_;
  transfer_stats stats_{};
  uint64_t instruction_index_ = 0;
  bool attached_ = false;

  const w1::runtime::module_catalog* modules_ = nullptr;
  const w1::util::memory_reader* memory_ = nullptr;

  w1::analysis::symbol_lookup symbol_lookup_{};
  std::unique_ptr<w1::analysis::abi_dispatcher> abi_dispatcher_{};
  std::unique_ptr<transfer_writer_jsonl> writer_{};

  std::unordered_set<uint64_t> unique_call_targets_;
  std::unordered_set<uint64_t> unique_return_sources_;

  bool capture_registers_ = false;
  bool capture_stack_ = false;
  bool enrich_modules_ = false;
  bool enrich_symbols_ = false;
  bool analyze_apis_ = false;
  bool emit_metadata_ = false;
};

} // namespace w1xfer
