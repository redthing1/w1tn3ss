#pragma once

#include "calling_convention_base.hpp"
#include "calling_convention_factory.hpp"
#include "calling_convention_detector.hpp"
#include "api_knowledge_db.hpp"
#include "../util/safe_memory.hpp"
#include <redlog.hpp>
#include <vector>
#include <string>
#include <variant>
#include <optional>
#include <memory>

namespace w1::abi {

// represents an extracted argument value with semantic meaning
struct extracted_argument {
  // raw value from register/stack
  uint64_t raw_value = 0;

  // semantic interpretation of the value
  std::variant<
      std::monostate,       // no interpretation
      int64_t,              // signed integer
      uint64_t,             // unsigned integer
      std::string,          // string (null-terminated)
      std::vector<uint8_t>, // raw buffer
      bool,                 // boolean
      double                // floating point
      >
      interpreted_value;

  // metadata about the argument
  param_info::type param_type = param_info::type::UNKNOWN;
  std::string param_name;
  std::string string_preview; // for pointers to strings
  std::string type_description;
  bool is_null_pointer = false;
  bool is_valid_pointer = false;

  // for buffers
  size_t buffer_size = 0;
  std::vector<uint8_t> buffer_preview; // first n bytes

  // for flags
  std::vector<std::string> flag_names; // decoded flag names
};

// represents all extracted arguments for an api call
struct extracted_call_info {
  std::string api_name;
  std::string module_name;
  std::vector<extracted_argument> arguments;
  extracted_argument return_value; // for post-call analysis

  // api metadata
  api_info::category category = api_info::category::UNKNOWN;
  uint32_t behavior_flags = 0;
  std::string description;

  // timing
  uint64_t timestamp = 0;
  uint64_t call_address = 0;
  uint64_t return_address = 0;
};

// configuration for argument extraction
struct extractor_config {
  size_t max_string_length = 256; // max chars to read for strings
  size_t max_buffer_preview = 64; // max bytes to preview for buffers
  bool follow_pointers = true;    // dereference pointers
  bool decode_flags = true;       // decode flag values
  bool extract_structs = false;   // attempt to parse known structs
  bool safe_memory_only = true;   // only read from safe memory regions
};

// context for a function call
struct call_context {
  QBDI::VMInstanceRef vm;
  QBDI::GPRState* gpr;
  QBDI::FPRState* fpr;
  uint64_t call_address;
  uint64_t target_address;
};

// extracts and interprets function arguments
class argument_extractor {
public:
  // new constructor that supports dynamic convention selection
  argument_extractor(
      std::shared_ptr<api_knowledge_db> api_db, std::shared_ptr<calling_convention_detector> detector = nullptr,
      const extractor_config& config = {}
  );

  // legacy constructor for compatibility
  argument_extractor(
      std::shared_ptr<calling_convention_base> convention, std::shared_ptr<api_knowledge_db> api_db,
      const extractor_config& config = {}
  );

  ~argument_extractor();

  // extract arguments for a function call with automatic convention detection
  extracted_call_info extract_call(
      const std::string& api_name, const std::string& module_name, const util::safe_memory_reader& memory,
      const call_context& ctx
  ) const;

  // extract with explicit convention
  extracted_call_info extract_call_with_convention(
      const std::string& api_name, const std::string& module_name, calling_convention_ptr convention,
      const util::safe_memory_reader& memory, const call_context& ctx
  ) const;

  // extract return value after function returns
  void extract_return_value(
      extracted_call_info& call_info, const util::safe_memory_reader& memory, const call_context& ctx
  ) const;

  // extract a single argument
  extracted_argument extract_argument(
      const param_info& param, uint64_t raw_value, const util::safe_memory_reader& memory
  ) const;

  // format extracted call for display
  std::string format_call(const extracted_call_info& call) const;

  // get/set configuration
  const extractor_config& get_config() const;
  void set_config(const extractor_config& config);

private:
  class impl;
  std::unique_ptr<impl> pimpl;
};

// utility functions for argument interpretation
namespace arg_utils {
// check if pointer looks valid
bool is_valid_pointer(uint64_t addr, const util::safe_memory_reader& memory);

// read null-terminated string
std::optional<std::string> read_string(uint64_t addr, const util::safe_memory_reader& memory, size_t max_length = 256);

// read wide string (windows)
std::optional<std::string> read_wide_string(
    uint64_t addr, const util::safe_memory_reader& memory, size_t max_length = 256
);

// format pointer value
std::string format_pointer(uint64_t addr);

// decode common flag values
std::vector<std::string> decode_flags(uint32_t flags, const std::string& flag_type);
} // namespace arg_utils

} // namespace w1::abi