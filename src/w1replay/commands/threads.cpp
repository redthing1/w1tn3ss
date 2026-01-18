#include "threads.hpp"

#include <iostream>
#include <vector>

#include <redlog.hpp>

#include "w1rewind/replay/replay_context.hpp"

namespace w1replay::commands {

int threads(const threads_options& options) {
  auto log = redlog::get_logger("w1replay.threads");

  if (options.trace_path.empty()) {
    log.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    return 1;
  }

  w1::rewind::replay_context context;
  std::string error;
  if (!w1::rewind::load_replay_context(options.trace_path, context, error)) {
    log.err("failed to load trace metadata", redlog::field("error", error));
    std::cerr << "error: " << error << std::endl;
    return 1;
  }

  if (context.threads.empty()) {
    std::cout << "no thread records found" << std::endl;
    return 0;
  }

  for (const auto& info : context.threads) {
    std::cout << "thread=" << info.thread_id;
    if (!info.name.empty()) {
      std::cout << " name=" << info.name;
    } else {
      std::cout << " name=unknown";
    }
    std::cout << " started=" << (info.started ? "true" : "false")
              << " ended=" << (info.ended ? "true" : "false") << std::endl;
  }

  return 0;
}

} // namespace w1replay::commands
