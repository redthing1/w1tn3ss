#include "replay_context.hpp"

#include "replay_context_builder.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace w1::rewind {

const module_record* replay_context::find_module_for_address(
    uint64_t address, uint64_t size, uint64_t& module_offset
) const {
  if (size == 0) {
    return nullptr;
  }

  for (const auto& module : modules) {
    if (address < module.base) {
      continue;
    }
    uint64_t offset = address - module.base;
    if (module.size < size) {
      continue;
    }
    if (offset > module.size - size) {
      continue;
    }
    module_offset = offset;
    return &module;
  }

  return nullptr;
}

bool replay_context::has_blocks() const { return (header.flags & trace_flag_blocks) != 0; }

bool replay_context::has_registers() const { return !register_specs.empty(); }

replay_context::trace_features replay_context::features() const {
  trace_features out{};
  out.has_registers = has_registers();
  out.has_memory_access = (header.flags & trace_flag_memory_access) != 0;
  out.has_memory_values = (header.flags & trace_flag_memory_values) != 0;
  out.has_stack_snapshot = (header.flags & trace_flag_stack_snapshot) != 0;
  out.has_blocks = has_blocks();
  out.track_memory = (out.has_memory_access && out.has_memory_values) || out.has_stack_snapshot;
  return out;
}

bool load_replay_context(const std::string& trace_path, replay_context& out, std::string& error) {
  error.clear();

  trace_reader reader(trace_path);
  if (!reader.open()) {
    error = reader.error();
    return false;
  }
  return build_replay_context(reader, out, error);
}

} // namespace w1::rewind
