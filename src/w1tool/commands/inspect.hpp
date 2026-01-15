#pragma once

#include <string>

namespace w1tool::commands {

struct inspect_request {
  std::string binary_path;
  bool show_headers = false;
  bool show_sections = false;
  bool show_segments = false;
  bool show_symbols = false;
  bool show_imports = false;
  bool show_exports = false;
  bool show_relocations = false;
  bool show_libraries = false;
  bool json_output = false;
  bool json_pretty = false;
  bool show_all = false;
  std::string forced_format;
};

/**
 * inspect command - comprehensive binary analysis using LIEF
 *
 * @param request resolved inspect configuration
 * @return exit code (0 for success, 1 for failure)
 */
int inspect(const inspect_request& request);

} // namespace w1tool::commands
