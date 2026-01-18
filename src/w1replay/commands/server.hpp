#pragma once

#include <cstdint>
#include <string>

namespace w1replay::commands {

struct server_options {
  std::string trace_path;
  std::string index_path;
  std::string checkpoint_path;
  std::string gdb_listen;
  uint64_t thread_id = 0;
  uint64_t start_sequence = 0;
  bool instruction_steps = false;
};

int server(const server_options& options);

} // namespace w1replay::commands
