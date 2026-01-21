#pragma once

#include <string>

namespace w1replay::commands {

struct threads_options {
  std::string trace_path;
};

int threads(const threads_options& options);

} // namespace w1replay::commands
