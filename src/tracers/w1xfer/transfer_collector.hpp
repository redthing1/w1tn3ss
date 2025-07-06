#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <QBDI.h>
#include <common/ext/jsonstruct.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/register_capture.hpp>
#include <w1tn3ss/util/stack_capture.hpp>
#include <w1tn3ss/util/value_formatter.hpp>
#include <w1tn3ss/abi/api_analyzer.hpp>
#include "symbol_enricher.hpp"

namespace w1xfer {

enum class transfer_type { CALL = 0, RETURN = 1 };

// register state is now a map of register names to values for JSON serialization
struct register_state {
  std::unordered_map<std::string, uint64_t> registers;

  JS_OBJECT(JS_MEMBER(registers));
};

struct stack_info {
  uint64_t stack_pointer;
  uint64_t frame_pointer;
  uint64_t return_address;
  std::vector<uint64_t> stack_values;

  JS_OBJECT(JS_MEMBER(stack_pointer), JS_MEMBER(frame_pointer), JS_MEMBER(return_address), JS_MEMBER(stack_values));
};

// Rich symbol information for transfer endpoints
struct symbol_info {
  std::string symbol_name;
  std::string demangled_name;
  uint64_t symbol_offset; // Offset within the symbol
  uint64_t module_offset; // Offset within the module
  bool is_exported;
  bool is_imported;

  JS_OBJECT(
      JS_MEMBER(symbol_name), JS_MEMBER(demangled_name), JS_MEMBER(symbol_offset), JS_MEMBER(module_offset),
      JS_MEMBER(is_exported), JS_MEMBER(is_imported)
  );
};

// API argument information
struct api_argument {
  uint64_t raw_value;
  std::string param_name;
  std::string param_type;
  std::string interpreted_value; // string representation of interpreted value
  bool is_pointer;

  JS_OBJECT(
      JS_MEMBER(raw_value), JS_MEMBER(param_name), JS_MEMBER(param_type), JS_MEMBER(interpreted_value),
      JS_MEMBER(is_pointer)
  );
};

// Return value information
struct api_return_value {
  uint64_t raw_value;
  std::string param_type;
  std::string interpreted_value;
  bool is_pointer;
  bool is_null;

  JS_OBJECT(
      JS_MEMBER(raw_value), JS_MEMBER(param_type), JS_MEMBER(interpreted_value), JS_MEMBER(is_pointer),
      JS_MEMBER(is_null)
  );
};

// API analysis information
struct api_analysis {
  std::string api_category;
  std::string description;
  std::vector<api_argument> arguments;
  api_return_value return_value;
  std::string formatted_call;
  bool analysis_complete;
  bool has_return_value;

  JS_OBJECT(
      JS_MEMBER(api_category), JS_MEMBER(description), JS_MEMBER(arguments), JS_MEMBER(return_value),
      JS_MEMBER(formatted_call), JS_MEMBER(analysis_complete), JS_MEMBER(has_return_value)
  );
};

struct transfer_entry {
  transfer_type type;
  uint64_t source_address;
  uint64_t target_address;
  uint64_t timestamp;
  uint64_t instruction_count;
  register_state registers;
  stack_info stack;
  std::string source_module;
  std::string target_module;
  // Rich symbol information
  symbol_info source_symbol;
  symbol_info target_symbol;
  // API analysis information
  api_analysis api_info;

  JS_OBJECT(
      JS_MEMBER(type), JS_MEMBER(source_address), JS_MEMBER(target_address), JS_MEMBER(timestamp),
      JS_MEMBER(instruction_count), JS_MEMBER(registers), JS_MEMBER(stack), JS_MEMBER(source_module),
      JS_MEMBER(target_module), JS_MEMBER(source_symbol), JS_MEMBER(target_symbol), JS_MEMBER(api_info)
  );
};

struct transfer_stats {
  uint64_t total_calls;
  uint64_t total_returns;
  uint64_t unique_call_targets;
  uint64_t unique_return_sources;
  uint64_t max_call_depth;
  uint64_t current_call_depth;

  JS_OBJECT(
      JS_MEMBER(total_calls), JS_MEMBER(total_returns), JS_MEMBER(unique_call_targets),
      JS_MEMBER(unique_return_sources), JS_MEMBER(max_call_depth), JS_MEMBER(current_call_depth)
  );
};

struct w1xfer_report {
  transfer_stats stats;
  std::vector<transfer_entry> trace;

  JS_OBJECT(JS_MEMBER(stats), JS_MEMBER(trace));
};

class transfer_collector {
public:
  explicit transfer_collector(
      uint64_t max_entries, bool log_registers, bool log_stack_info, bool log_call_targets, bool analyze_apis = false,
      bool collect_trace = true
  );

  void initialize_module_tracking();

  void record_call(
      uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  void record_return(
      uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  w1xfer_report build_report() const;

  const transfer_stats& get_stats() const { return stats_; }
  size_t get_trace_size() const { return trace_.size(); }
  uint64_t get_instruction_count() const { return instruction_count_; }

  std::string get_module_name(uint64_t address) const;

private:
  transfer_stats stats_;
  std::vector<transfer_entry> trace_;
  uint64_t max_entries_;
  uint64_t instruction_count_;
  bool log_registers_;
  bool log_stack_info_;
  bool log_call_targets_;
  bool analyze_apis_;
  bool collect_trace_;
  bool trace_overflow_;
  w1::util::module_scanner scanner_;
  w1::util::module_range_index index_;
  bool modules_initialized_;
  std::unique_ptr<symbol_enricher> symbol_enricher_;
  std::unique_ptr<w1::abi::api_analyzer> api_analyzer_;

  // Call stack tracking for return value analysis
  struct pending_call {
    uint64_t call_target_address;
    std::string target_symbol_name;
    std::string target_module;
    w1::abi::api_info api_info;
    uint64_t timestamp;
  };
  std::vector<pending_call> call_stack_;

  uint64_t get_timestamp() const;
  void update_call_depth(transfer_type type);
  symbol_info enrich_symbol(uint64_t address) const;

  // helper methods to reduce code duplication
  bool should_collect_trace() const;
  transfer_entry create_base_entry(transfer_type type, uint64_t source_addr, uint64_t target_addr) const;
  void populate_entry_details(
      transfer_entry& entry, uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr
  ) const;
};

} // namespace w1xfer

// custom serialization for transfer_type enum outside namespace
namespace JS {
template <> struct TypeHandler<w1xfer::transfer_type> {
  static inline void from(const w1xfer::transfer_type& from_type, Token& token, Serializer& serializer) {
    std::string type_str = (from_type == w1xfer::transfer_type::CALL) ? "call" : "return";
    TypeHandler<std::string>::from(type_str, token, serializer);
  }
  static inline void to(w1xfer::transfer_type& to_type, ParseContext& context) {
    std::string type_str;
    TypeHandler<std::string>::to(type_str, context);
    to_type = (type_str == "call") ? w1xfer::transfer_type::CALL : w1xfer::transfer_type::RETURN;
  }
};
} // namespace JS