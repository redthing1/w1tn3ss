#pragma once

#include <string>

namespace w1replay::commands {

struct summary_options {
  std::string trace_path;
  std::string index_path;
  std::string checkpoint_path;
  bool full = false;
};

int summary(const summary_options& options);

} // namespace w1replay::commands
