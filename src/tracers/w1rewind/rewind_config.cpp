#include "rewind_config.hpp"

#include "w1base/env_config.hpp"

namespace w1rewind {

rewind_config rewind_config::from_environment() {
  w1::util::env_config loader("W1REWIND");

  rewind_config config;
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
  config.record_instructions = loader.get<bool>("RECORD_INSTRUCTIONS", config.record_instructions);
  config.record_register_deltas = loader.get<bool>("RECORD_REGISTER_DELTAS", config.record_register_deltas);
  config.snapshot_interval = loader.get<uint64_t>("SNAPSHOT_INTERVAL", config.snapshot_interval);
  config.stack_snapshot_bytes = loader.get<uint64_t>("STACK_SNAPSHOT", config.stack_snapshot_bytes);
  config.memory.enabled = loader.get<bool>("MEMORY", false);
  config.memory.include_reads = loader.get<bool>("MEMORY_READS", false);
  config.memory.include_values = loader.get<bool>("MEMORY_VALUES", false);
  config.memory.max_value_bytes = loader.get<uint32_t>("MEMORY_MAX_BYTES", config.memory.max_value_bytes);
  config.output_path = loader.get<std::string>("OUTPUT", "");
  config.compress_trace = loader.get<bool>("COMPRESS", config.compress_trace);
  config.chunk_size = loader.get<uint32_t>("CHUNK_SIZE", config.chunk_size);

  return config;
}

bool rewind_config::requires_instruction_flow() const {
  return record_instructions || record_register_deltas || memory.enabled;
}

} // namespace w1rewind
