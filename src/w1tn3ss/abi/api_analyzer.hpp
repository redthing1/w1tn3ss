#pragma once

#include "argument_extractor.hpp"
#include "api_knowledge_db.hpp"
#include "calling_convention_detector.hpp"
#include "../lief/lief_symbol_resolver.hpp"
#include "../util/safe_memory.hpp"
#include "../util/module_range_index.hpp"
#include <QBDI.h>
#include <memory>
#include <optional>
#include <string>

namespace w1::abi {

// context for api analysis
struct api_context {
  // basic call information
  uint64_t call_address;
  uint64_t target_address;
  std::string module_name;
  std::string symbol_name;

  // qbdi context
  QBDI::VMInstanceRef vm;
  const QBDI::VMState* vm_state;
  QBDI::GPRState* gpr_state;
  QBDI::FPRState* fpr_state;

  // module information
  const util::module_range_index* module_index;

  // timing
  uint64_t timestamp;
};

// result of api analysis
struct api_analysis_result {
  // symbol information
  std::string symbol_name;
  std::string demangled_name;
  std::string module_name;
  uint64_t module_offset;

  // api semantics
  api_info::category category = api_info::category::UNKNOWN;
  uint32_t behavior_flags = 0;
  std::string description;

  // extracted arguments
  std::vector<extracted_argument> arguments;

  // for return analysis
  extracted_argument return_value;

  // formatted call string
  std::string formatted_call;

  // error information
  bool analysis_complete = false;
  std::string error_message;
};

// configuration for api analyzer
struct analyzer_config {
  // feature toggles
  bool resolve_symbols = true;
  bool extract_arguments = true;
  bool format_calls = true;
  bool safe_memory_only = true;

  // limits
  size_t max_string_length = 256;
  size_t max_buffer_preview = 64;
  size_t max_arguments = 16;

  // logging
  bool verbose = false;
};

// main api analyzer class
class api_analyzer {
public:
  api_analyzer(const analyzer_config& config = {});
  ~api_analyzer();

  // initialize with module information
  void initialize(const util::module_range_index& module_index);

  // analyze an api call
  api_analysis_result analyze_call(const api_context& ctx);

  // analyze return from api call
  void analyze_return(api_analysis_result& result, const api_context& ctx);

  // get api database for queries
  const api_knowledge_db& get_api_db() const;

  // get statistics
  struct stats {
    uint64_t calls_analyzed = 0;
    uint64_t symbols_resolved = 0;
    uint64_t arguments_extracted = 0;
    uint64_t apis_identified = 0;
    uint64_t errors = 0;
  };
  stats get_stats() const;

  // clear caches
  void clear_caches();

private:
  class impl;
  std::unique_ptr<impl> pimpl;
};

// helper functions
namespace analysis_utils {
// check if an address is likely an api call
bool is_api_call(uint64_t address, const util::module_range_index& modules);

// format an api call with arguments for display
std::string format_api_call(const std::string& api_name, const std::vector<extracted_argument>& args);

// get a short description of api behavior
std::string describe_api_behavior(const api_info& info);
} // namespace analysis_utils

} // namespace w1::abi