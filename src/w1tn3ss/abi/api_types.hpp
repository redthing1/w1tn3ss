#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <QBDI.h>

#include "api_knowledge_db.hpp"
#include "argument_extractor.hpp"

namespace w1::util {
class module_range_index;
}

namespace w1::abi {

struct api_context {
  uint64_t call_address = 0;
  uint64_t target_address = 0;
  std::string module_name;
  std::string symbol_name;

  QBDI::VMInstanceRef vm = nullptr;
  const QBDI::VMState* vm_state = nullptr;
  QBDI::GPRState* gpr_state = nullptr;
  QBDI::FPRState* fpr_state = nullptr;

  const util::module_range_index* module_index = nullptr;

  uint64_t timestamp = 0;
};

struct api_analysis_result {
  std::string symbol_name;
  std::string demangled_name;
  std::string module_name;
  uint64_t module_offset = 0;

  api_info::category category = api_info::category::UNKNOWN;
  uint32_t behavior_flags = 0;
  std::string description;

  std::vector<extracted_argument> arguments;
  extracted_argument return_value;
  param_info return_param;

  std::string formatted_call;

  bool found_in_knowledge_db = false;
  bool analysis_complete = false;
  bool has_return_value = false;
  std::string error_message;
};

struct api_event_argument {
  uint64_t raw_value = 0;
  std::string param_name;
  param_info::type param_type = param_info::type::UNKNOWN;
  bool is_pointer = false;
  std::string interpreted_value;
};

struct api_event_return {
  uint64_t raw_value = 0;
  param_info::type param_type = param_info::type::UNKNOWN;
  bool is_pointer = false;
  std::string interpreted_value;
};

struct api_event {
  enum class event_type { CALL, RETURN };

  event_type type = event_type::CALL;
  uint64_t timestamp = 0;
  uint64_t source_address = 0;
  uint64_t target_address = 0;

  std::string module_name;
  std::string symbol_name;

  api_info::category category = api_info::category::UNKNOWN;
  std::string description;
  std::string formatted_call;
  bool analysis_complete = false;
  bool has_return_value = false;

  std::vector<api_event_argument> arguments;
  std::optional<api_event_return> return_value;
};

} // namespace w1::abi
