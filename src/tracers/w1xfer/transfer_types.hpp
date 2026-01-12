#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace w1xfer {

enum class transfer_type { CALL = 0, RETURN = 1 };

struct transfer_event {
  transfer_type type = transfer_type::CALL;
  uint64_t source_address = 0;
  uint64_t target_address = 0;
  uint64_t instruction_index = 0;
  uint64_t timestamp = 0;
  uint64_t thread_id = 0;
  uint64_t call_depth = 0;
};

struct transfer_registers {
  std::unordered_map<std::string, uint64_t> values;
};

struct transfer_stack {
  uint64_t stack_pointer = 0;
  uint64_t frame_pointer = 0;
  uint64_t return_address = 0;
  std::vector<uint64_t> values;
};

struct transfer_symbol {
  std::string module_name;
  std::string symbol_name;
  std::string demangled_name;
  uint64_t symbol_offset = 0;
  uint64_t module_offset = 0;
  bool is_exported = false;
  bool is_imported = false;
};

struct transfer_endpoint {
  uint64_t address = 0;
  std::string module_name;
  uint64_t module_offset = 0;
  std::optional<transfer_symbol> symbol;
};

struct transfer_api_argument {
  uint64_t raw_value = 0;
  std::string name;
  std::string type;
  std::string interpreted_value;
  bool is_pointer = false;
};

struct transfer_api_return {
  uint64_t raw_value = 0;
  std::string type;
  std::string interpreted_value;
  bool is_pointer = false;
  bool is_null = false;
};

struct transfer_api_info {
  std::string category;
  std::string description;
  std::string formatted_call;
  bool analysis_complete = false;
  bool has_return_value = false;
  std::vector<transfer_api_argument> arguments;
  std::optional<transfer_api_return> return_value;
};

struct transfer_record {
  transfer_event event;
  std::optional<transfer_registers> registers;
  std::optional<transfer_stack> stack;
  std::optional<transfer_endpoint> source;
  std::optional<transfer_endpoint> target;
  std::optional<transfer_api_info> api;
};

struct transfer_stats {
  uint64_t total_calls = 0;
  uint64_t total_returns = 0;
  uint64_t unique_call_targets = 0;
  uint64_t unique_return_sources = 0;
  uint64_t max_call_depth = 0;
  uint64_t current_call_depth = 0;
};

} // namespace w1xfer
