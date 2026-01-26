#include "rewind_config.hpp"

#include <algorithm>

#include "w1base/env_config.hpp"
#include "w1base/interval.hpp"
#include "w1base/parse_utils.hpp"

namespace w1rewind {
rewind_config rewind_config::from_environment(std::string& error) {
  error.clear();
  w1::util::env_config loader("W1REWIND");
  using flow_options = rewind_config::flow_options;
  using register_options = rewind_config::register_options;
  using stack_window_options = rewind_config::stack_window_options;
  using memory_access = rewind_config::memory_access;
  using memory_filter_kind = rewind_config::memory_filter_kind;

  rewind_config config;
  config.common = w1::instrument::config::load_common(loader);
  config.threads = w1::instrument::config::load_thread_attach_policy(
      loader, w1::instrument::config::thread_attach_policy::main_only
  );

  std::string flow_value = loader.get<std::string>("FLOW", "");
  if (!flow_value.empty()) {
    if (!w1::util::parse_enum(
            flow_value,
            {{"instruction", flow_options::flow_mode::instruction}, {"block", flow_options::flow_mode::block}},
            config.flow.mode
        )) {
      error = "invalid W1REWIND_FLOW value";
      return config;
    }
  }

  std::string reg_capture = loader.get<std::string>("REG_CAPTURE", "");
  if (!reg_capture.empty()) {
    if (!w1::util::parse_enum(reg_capture, {{"gpr", register_options::capture_kind::gpr}}, config.registers.capture)) {
      error = "invalid W1REWIND_REG_CAPTURE value";
      return config;
    }
  }

  config.registers.deltas = loader.get<bool>("REG_DELTAS", config.registers.deltas);
  config.registers.snapshot_interval =
      loader.get<uint64_t>("REG_SNAPSHOT_INTERVAL", config.registers.snapshot_interval);
  config.registers.bytes = loader.get<bool>("REG_BYTES", config.registers.bytes);

  std::string stack_mode = loader.get<std::string>("STACK_WINDOW_MODE", "");
  if (!stack_mode.empty()) {
    if (!w1::util::parse_enum(
            stack_mode,
            {{"none", stack_window_options::window_mode::none},
             {"fixed", stack_window_options::window_mode::fixed},
             {"frame", stack_window_options::window_mode::frame}},
            config.stack_window.mode
        )) {
      error = "invalid W1REWIND_STACK_WINDOW_MODE value";
      return config;
    }
  }
  config.stack_window.above_bytes = loader.get<uint64_t>("STACK_WINDOW_ABOVE", config.stack_window.above_bytes);
  config.stack_window.below_bytes = loader.get<uint64_t>("STACK_WINDOW_BELOW", config.stack_window.below_bytes);
  config.stack_window.max_total_bytes = loader.get<uint64_t>("STACK_WINDOW_MAX", config.stack_window.max_total_bytes);
  config.stack_snapshots.interval = loader.get<uint64_t>("STACK_SNAPSHOT_INTERVAL", config.stack_snapshots.interval);

  std::string mem_access = loader.get<std::string>("MEM_ACCESS", "");
  if (!mem_access.empty()) {
    if (!w1::util::parse_enum(
            mem_access,
            {{"none", memory_access::none},
             {"reads", memory_access::reads},
             {"writes", memory_access::writes},
             {"reads_writes", memory_access::reads_writes}},
            config.memory.access
        )) {
      error = "invalid W1REWIND_MEM_ACCESS value";
      return config;
    }
  }

  config.memory.values = loader.get<bool>("MEM_VALUES", config.memory.values);
  config.memory.max_value_bytes = loader.get<uint32_t>("MEM_MAX_BYTES", config.memory.max_value_bytes);

  auto filters = loader.get_list("MEM_FILTER");
  config.memory.filters.clear();
  if (filters.empty()) {
    config.memory.filters.push_back(memory_filter_kind::all);
  } else {
    bool saw_all = false;
    bool saw_ranges = false;
    bool saw_stack = false;
    for (const auto& entry : filters) {
      const std::string value = w1::util::to_lower(entry);
      if (value == "all") {
        saw_all = true;
      } else if (value == "ranges") {
        saw_ranges = true;
      } else if (value == "stack_window") {
        saw_stack = true;
      } else {
        error = "invalid W1REWIND_MEM_FILTER value";
        return config;
      }
    }
    if (saw_all && (saw_ranges || saw_stack)) {
      error = "memory filter 'all' cannot be combined with other selectors";
      return config;
    }
    if (saw_all) {
      config.memory.filters.push_back(memory_filter_kind::all);
    } else {
      if (saw_ranges) {
        config.memory.filters.push_back(memory_filter_kind::ranges);
      }
      if (saw_stack) {
        config.memory.filters.push_back(memory_filter_kind::stack_window);
      }
    }
  }

  auto ranges = loader.get_list("MEM_RANGES");
  config.memory.ranges.clear();
  if (!ranges.empty()) {
    config.memory.ranges.reserve(ranges.size());
    for (const auto& entry : ranges) {
      w1::address_range range{};
      std::string parse_error;
      if (!w1::util::parse_address_range(entry, range, &parse_error)) {
        error = "invalid W1REWIND_MEM_RANGES entry: " + parse_error;
        return config;
      }
      config.memory.ranges.push_back(range);
    }
    w1::util::merge_ranges(config.memory.ranges);
  }

  config.image_blobs.enabled = loader.get<bool>("IMAGE_BLOBS", config.image_blobs.enabled);
  config.image_blobs.exec_only = loader.get<bool>("IMAGE_BLOBS_EXEC_ONLY", config.image_blobs.exec_only);
  config.image_blobs.max_bytes = loader.get<uint64_t>("IMAGE_BLOBS_MAX", config.image_blobs.max_bytes);

  config.output_path = loader.get<std::string>("OUTPUT", "");
  config.compress_trace = loader.get<bool>("COMPRESS", config.compress_trace);
  config.chunk_size = loader.get<uint32_t>("CHUNK_SIZE", config.chunk_size);

  auto module_filter_env = loader.get_list("MODULE_FILTER");
  if (!module_filter_env.empty()) {
    config.common.instrumentation.include_modules.insert(
        config.common.instrumentation.include_modules.end(), module_filter_env.begin(), module_filter_env.end()
    );
  }

  if (!config.validate(error)) {
    return config;
  }

  return config;
}

bool rewind_config::validate(std::string& error) const {
  error.clear();
  using register_options = rewind_config::register_options;
  using stack_window_options = rewind_config::stack_window_options;
  using flow_options = rewind_config::flow_options;
  using memory_access = rewind_config::memory_access;
  using memory_filter_kind = rewind_config::memory_filter_kind;

  if (registers.capture != register_options::capture_kind::gpr) {
    error = "register capture mode not supported";
    return false;
  }

  if (registers.bytes) {
    error = "register byte capture not supported";
    return false;
  }

  if (flow.mode == flow_options::flow_mode::block) {
    if (registers.deltas) {
      error = "flow=block incompatible with reg_deltas";
      return false;
    }
    if (memory.access != memory_access::none) {
      error = "flow=block incompatible with mem_access";
      return false;
    }
  }

  if (stack_snapshots.interval > 0 && stack_window.mode == stack_window_options::window_mode::none) {
    error = "stack snapshots require stack window mode";
    return false;
  }

  if (stack_window.mode != stack_window_options::window_mode::none && stack_window.max_total_bytes == 0) {
    error = "stack window max_total_bytes must be non-zero";
    return false;
  }

  if (stack_window.mode == stack_window_options::window_mode::fixed &&
      (stack_window.above_bytes + stack_window.below_bytes) == 0) {
    error = "fixed stack window requires above or below bytes";
    return false;
  }

  if (stack_window.mode == stack_window_options::window_mode::frame && stack_window.max_total_bytes < 16) {
    error = "frame stack window requires max_total_bytes >= 16";
    return false;
  }

  if (memory.values && memory.access == memory_access::none) {
    error = "memory values require memory.access";
    return false;
  }

  bool filter_all =
      std::find(memory.filters.begin(), memory.filters.end(), memory_filter_kind::all) != memory.filters.end();
  bool filter_ranges =
      std::find(memory.filters.begin(), memory.filters.end(), memory_filter_kind::ranges) != memory.filters.end();
  bool filter_stack =
      std::find(memory.filters.begin(), memory.filters.end(), memory_filter_kind::stack_window) != memory.filters.end();

  if (filter_all && (filter_ranges || filter_stack)) {
    error = "memory.filter=all cannot be combined with other filters";
    return false;
  }

  if (filter_ranges && memory.ranges.empty()) {
    error = "memory.filter=ranges requires MEM_RANGES";
    return false;
  }

  if (filter_stack && stack_window.mode == stack_window_options::window_mode::none) {
    error = "memory.filter=stack_window requires stack window mode";
    return false;
  }

  return true;
}

} // namespace w1rewind
