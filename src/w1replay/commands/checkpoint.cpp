#include "checkpoint.hpp"

#include <iostream>

#include <redlog.hpp>

#include "w1tn3ss/runtime/rewind/replay_checkpoint.hpp"

namespace w1replay::commands {

int checkpoint(const checkpoint_options& options) {
  auto log = redlog::get_logger("w1replay.checkpoint");

  if (options.trace_path.empty()) {
    log.err("trace path required");
    std::cerr << "error: --trace is required" << std::endl;
    return 1;
  }
  if (options.stride == 0) {
    log.err("checkpoint stride must be non-zero");
    std::cerr << "error: --stride must be > 0" << std::endl;
    return 1;
  }

  w1::rewind::replay_checkpoint_config config{};
  config.trace_path = options.trace_path;
  config.output_path = options.output_path;
  config.stride = options.stride;
  config.include_memory = options.include_memory;
  config.thread_id = options.thread_id;

  w1::rewind::replay_checkpoint_index index;
  std::string error;
  if (!w1::rewind::build_replay_checkpoint(config, &index, error)) {
    log.err("failed to build checkpoint", redlog::field("error", error));
    std::cerr << "error: " << (error.empty() ? "failed to build checkpoint" : error) << std::endl;
    return 1;
  }

  std::string output = options.output_path.empty()
                           ? w1::rewind::default_replay_checkpoint_path(options.trace_path)
                           : options.output_path;

  log.inf("checkpoint written", redlog::field("path", output));
  std::cout << "wrote checkpoint: " << output << std::endl;
  return 0;
}

} // namespace w1replay::commands
