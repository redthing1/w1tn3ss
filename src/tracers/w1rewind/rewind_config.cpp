#include "rewind_config.hpp"

#include "w1tn3ss/util/env_config.hpp"

namespace w1rewind {

rewind_config rewind_config::from_environment() {
  w1::util::env_config loader("W1REWIND");

  rewind_config config;
  // suppress noisy modules that cause spurious mismatches by default.
  config.ignore_modules = {"libqbdi", "libqbdipreload", "qbdi", "libsystem", "libc"};

  using system_policy = w1::core::system_module_policy;
  system_policy policy = system_policy::exclude_all;
  policy = loader.get_enum<system_policy>(
      {
          {"exclude", system_policy::exclude_all},
          {"exclude_all", system_policy::exclude_all},
          {"none", system_policy::exclude_all},
          {"critical", system_policy::include_critical},
          {"include_critical", system_policy::include_critical},
          {"all", system_policy::include_all},
          {"include_all", system_policy::include_all},
          {"include", system_policy::include_all},
      },
      "SYSTEM_POLICY", policy
  );
  config.instrumentation.system_policy = policy;
  config.instrumentation.include_unnamed_modules = loader.get<bool>("INCLUDE_UNNAMED", false);
  config.instrumentation.use_default_excludes = loader.get<bool>("USE_DEFAULT_EXCLUDES", true);
  config.instrumentation.include_modules = loader.get_list("INCLUDE");
  config.instrumentation.exclude_modules = loader.get_list("EXCLUDE");
  auto module_filter_env = loader.get_list("MODULE_FILTER");
  if (!module_filter_env.empty()) {
    config.instrumentation.include_modules.insert(
        config.instrumentation.include_modules.end(), module_filter_env.begin(), module_filter_env.end()
    );
  }

  config.exclude_self = loader.get<bool>("EXCLUDE_SELF", true);
  config.verbose = loader.get<int>("VERBOSE", 0);
  config.record_instructions = loader.get<bool>("RECORD_INSTRUCTIONS", true);
  config.record_registers = loader.get<bool>("RECORD_REGISTERS", true);
  config.record_memory = loader.get<bool>("RECORD_MEMORY", true);
  config.capture_memory_reads = loader.get<bool>("CAPTURE_MEMORY_READS", false);
  config.frame_instruction_interval = loader.get<uint64_t>("FRAME_INTERVAL", 0);
  config.output_path = loader.get<std::string>("OUTPUT", "");
  config.compare_trace_path = loader.get<std::string>("COMPARE_TRACE", "");

  const auto mode_str = loader.get<std::string>("VALIDATION_MODE", "none");
  if (mode_str == "log" || mode_str == "log_only") {
    config.mode = rewind_config::validation_mode::log_only;
  } else if (mode_str == "strict") {
    config.mode = rewind_config::validation_mode::strict;
  } else {
    config.mode = rewind_config::validation_mode::none;
  }

  config.max_mismatches = loader.get<uint64_t>("MAX_MISMATCHES", 1);
  config.stack_window_bytes = loader.get<uint64_t>("STACK_WINDOW", config.stack_window_bytes);

  auto ignore_regs_env = loader.get_list("VALIDATION_IGNORE_REGS");
  if (!ignore_regs_env.empty()) {
    config.ignore_registers.insert(config.ignore_registers.end(), ignore_regs_env.begin(), ignore_regs_env.end());
  }

  auto ignore_modules_env = loader.get_list("VALIDATION_IGNORE_MODULES");
  if (!ignore_modules_env.empty()) {
    config.ignore_modules.insert(config.ignore_modules.end(), ignore_modules_env.begin(), ignore_modules_env.end());
  }

  return config;
}

} // namespace w1rewind
