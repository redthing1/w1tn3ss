#pragma once

#include <optional>
#include <string>

namespace w1::import_insertion {

// comprehensive cross-platform error codes
enum class error_code {
  success,

  // file errors
  file_not_found,
  file_access_denied,
  invalid_output_path,
  output_already_exists,

  // binary format errors
  invalid_binary_format,
  unknown_magic_number,
  unsupported_architecture,
  corrupted_header,

  // library import errors
  duplicate_library,
  library_path_invalid,
  insufficient_space,

  // code signature errors
  code_signature_conflict,
  code_signature_removal_failed,

  // user interaction errors
  user_declined,
  interactive_prompt_failed,

  // platform errors
  platform_not_supported,
  insufficient_privileges,

  // system errors
  out_of_memory,
  system_error,
  configuration_invalid,

  unknown_error
};

// configuration for library import insertion
struct config {
  // REQUIRED
  std::string library_path;  // path to library to insert
  std::string target_binary; // path to target binary

  // OUTPUT HANDLING
  std::optional<std::string> output_path; // if not set, uses target_binary + "_patched"
  bool in_place = false;                  // modify target_binary directly
  bool overwrite_existing = false;        // overwrite output file if it exists

  // LIBRARY IMPORT OPTIONS
  bool weak_import = false;          // use weak import (LC_LOAD_WEAK_DYLIB on macos)
  bool strip_code_signature = false; // automatically remove code signature if present

  // USER INTERACTION
  bool assume_yes = false; // answer yes to all prompts (equivalent to --all-yes)
};

// result of library import insertion
struct result {
  error_code code;
  std::string error_message;
  std::optional<int> system_error_code;

  // convenience
  bool success() const { return code == error_code::success; }
  operator bool() const { return success(); }
};

// MAIN LIBRARY IMPORT INSERTION FUNCTION
result insert_library_import(const config& cfg);

// UTILITIES
std::string error_code_to_string(error_code code);
bool is_recoverable_error(error_code code);
bool is_platform_supported();
std::string get_platform_support_info();

} // namespace w1::import_insertion