#include "threads.hpp"

#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <vector>

#include <redlog.hpp>

#include "w1tn3ss/runtime/rewind/trace_reader.hpp"

namespace w1replay::commands {

namespace {

struct thread_info {
  std::string name;
  bool started = false;
  bool ended = false;
};

} // namespace

int threads(const threads_options& options) {
  auto log = redlog::get_logger("w1replay.threads");

  if (options.trace_path.empty()) {
    log.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    return 1;
  }

  w1::rewind::trace_reader reader(options.trace_path);
  if (!reader.open()) {
    log.err("failed to open trace", redlog::field("error", reader.error()));
    std::cerr << "error: " << reader.error() << std::endl;
    return 1;
  }

  std::unordered_map<uint64_t, thread_info> threads;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<w1::rewind::thread_start_record>(record)) {
      const auto& start = std::get<w1::rewind::thread_start_record>(record);
      auto& info = threads[start.thread_id];
      info.started = true;
      if (info.name.empty() && !start.name.empty()) {
        info.name = start.name;
      }
    } else if (std::holds_alternative<w1::rewind::thread_end_record>(record)) {
      const auto& end = std::get<w1::rewind::thread_end_record>(record);
      auto& info = threads[end.thread_id];
      info.ended = true;
    }
  }

  if (!reader.error().empty()) {
    log.err("trace read failed", redlog::field("error", reader.error()));
    std::cerr << "error: " << reader.error() << std::endl;
    return 1;
  }

  if (threads.empty()) {
    std::cout << "no thread records found" << std::endl;
    return 0;
  }

  std::vector<uint64_t> ids;
  ids.reserve(threads.size());
  for (const auto& entry : threads) {
    ids.push_back(entry.first);
  }
  std::sort(ids.begin(), ids.end());

  for (uint64_t id : ids) {
    const auto& info = threads.at(id);
    std::cout << "thread=" << id;
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
