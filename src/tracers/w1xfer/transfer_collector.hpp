#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <QBDI.h>
#include <redlog.hpp>
#include <w1common/ext/jsonstruct.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/register_capture.hpp>
#include <w1tn3ss/util/stack_capture.hpp>
#include <w1tn3ss/util/value_formatter.hpp>
#include <w1tn3ss/util/jsonl_writer.hpp>
#include <w1tn3ss/abi/api_listener.hpp>
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

// rich symbol information for transfer endpoints
struct symbol_info {
  std::string symbol_name;
  std::string demangled_name;
  uint64_t symbol_offset; // offset within the symbol
  uint64_t module_offset; // offset within the module
  bool is_exported;
  bool is_imported;

  JS_OBJECT(
      JS_MEMBER(symbol_name), JS_MEMBER(demangled_name), JS_MEMBER(symbol_offset), JS_MEMBER(module_offset),
      JS_MEMBER(is_exported), JS_MEMBER(is_imported)
  );
};

// api argument information
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

// return value information
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

// api analysis information
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
  uint64_t instruction_count;
  register_state registers;
  stack_info stack;
  std::string source_module;
  std::string target_module;
  // rich symbol information
  symbol_info source_symbol;
  symbol_info target_symbol;
  // api analysis information
  api_analysis api_info;

  JS_OBJECT(
      JS_MEMBER(type), JS_MEMBER(source_address), JS_MEMBER(target_address), JS_MEMBER(instruction_count),
      JS_MEMBER(registers), JS_MEMBER(stack), JS_MEMBER(source_module), JS_MEMBER(target_module),
      JS_MEMBER(source_symbol), JS_MEMBER(target_symbol), JS_MEMBER(api_info)
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

// removed w1xfer_report - we now stream directly

class transfer_collector {
public:
  explicit transfer_collector(
      const std::string& output_file, bool log_registers, bool log_stack_info, bool log_call_targets,
      bool analyze_apis = false
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

  const transfer_stats& get_stats() const { return stats_; }
  uint64_t get_instruction_count() const { return instruction_count_; }

  std::string get_module_name(uint64_t address) const;

private:
  transfer_stats stats_;
  uint64_t instruction_count_;
  bool log_registers_;
  bool log_stack_info_;
  bool log_call_targets_;
  bool analyze_apis_;
  w1::util::module_scanner scanner_;
  w1::util::module_range_index index_;
  bool modules_initialized_;
  std::unique_ptr<symbol_enricher> symbol_enricher_;
  std::unique_ptr<w1::abi::api_listener> api_listener_;
  redlog::logger log_ = redlog::get_logger("w1.transfer_collector");

  // output handling
  std::unique_ptr<w1::util::jsonl_writer> jsonl_writer_;
  bool metadata_written_ = false;

  // unique target tracking for stats
  std::unordered_set<uint64_t> unique_call_targets_;
  std::unordered_set<uint64_t> unique_return_sources_;

  void update_call_depth(transfer_type type);
  symbol_info enrich_symbol(uint64_t address) const;

  // helper methods to reduce code duplication
  transfer_entry create_base_entry(transfer_type type, uint64_t source_addr, uint64_t target_addr) const;
  void populate_entry_details(
      transfer_entry& entry, uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr
  ) const;

  // api event handlers
  void on_api_event(const w1::abi::api_event& event, transfer_entry& entry);

  // output helpers
  void ensure_metadata_written();
  void write_metadata();
  void write_event(const transfer_entry& entry);
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