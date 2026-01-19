#include "replay_context.hpp"

#include <algorithm>
#include <unordered_map>

#include "replay_registers.hpp"
#include "trace_reader.hpp"

namespace w1::rewind {

namespace {

std::optional<uint16_t> find_register_with_flag(const std::vector<register_spec>& specs, uint16_t flag) {
  for (const auto& spec : specs) {
    if ((spec.flags & flag) != 0) {
      return spec.reg_id;
    }
  }
  return std::nullopt;
}

} // namespace

const module_record* replay_context::find_module_for_address(
    uint64_t address,
    uint64_t size,
    uint64_t& module_offset
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
  out.track_memory = out.has_registers && ((out.has_memory_access && out.has_memory_values) || out.has_stack_snapshot);
  return out;
}

bool load_replay_context(const std::string& trace_path, replay_context& out, std::string& error) {
  error.clear();

  trace_reader reader(trace_path);
  if (!reader.open()) {
    error = reader.error();
    return false;
  }

  replay_context context;
  context.header = reader.header();

  std::unordered_map<uint64_t, replay_thread_info> thread_map;

  trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<target_info_record>(record)) {
      context.target_info = std::get<target_info_record>(record);
    } else if (std::holds_alternative<register_spec_record>(record)) {
      context.register_specs = std::get<register_spec_record>(record).registers;
    } else if (std::holds_alternative<register_table_record>(record)) {
      context.register_names = std::get<register_table_record>(record).names;
    } else if (std::holds_alternative<module_table_record>(record)) {
      context.modules = std::get<module_table_record>(record).modules;
    } else if (std::holds_alternative<memory_map_record>(record)) {
      context.memory_map = std::get<memory_map_record>(record).regions;
    } else if (std::holds_alternative<block_definition_record>(record)) {
      const auto& def = std::get<block_definition_record>(record);
      context.blocks_by_id[def.block_id] = def;
    } else if (std::holds_alternative<thread_start_record>(record)) {
      const auto& start = std::get<thread_start_record>(record);
      auto& info = thread_map[start.thread_id];
      info.thread_id = start.thread_id;
      info.started = true;
      if (!start.name.empty() && info.name.empty()) {
        info.name = start.name;
      }
    } else if (std::holds_alternative<thread_end_record>(record)) {
      const auto& end = std::get<thread_end_record>(record);
      auto& info = thread_map[end.thread_id];
      info.thread_id = end.thread_id;
      info.ended = true;
    }
  }

  if (!reader.error().empty()) {
    error = reader.error();
    return false;
  }

  if (!context.target_info.has_value()) {
    error = "target info missing";
    return false;
  }
  if (context.header.arch.arch_family == w1::arch::family::unknown ||
      context.header.arch.arch_mode == w1::arch::mode::unknown) {
    error = "trace arch spec missing";
    return false;
  }
  if (context.header.arch.pointer_bits == 0 || (context.header.arch.pointer_bits % 8) != 0) {
    error = "trace pointer bits invalid";
    return false;
  }
  if (context.header.arch.arch_byte_order == w1::arch::byte_order::unknown) {
    error = "trace byte order missing";
    return false;
  }
  if (context.register_specs.empty()) {
    error = "register specs missing";
    return false;
  }

  uint16_t max_reg_id = 0;
  for (const auto& spec : context.register_specs) {
    if (spec.reg_id > max_reg_id) {
      max_reg_id = spec.reg_id;
    }
    if (spec.name.empty()) {
      error = "register spec name missing";
      return false;
    }
    if (spec.bits == 0) {
      error = "register spec bits missing";
      return false;
    }
  }

  const size_t expected_count = static_cast<size_t>(max_reg_id) + 1;
  if (expected_count != context.register_specs.size()) {
    error = "register ids must be contiguous";
    return false;
  }

  std::vector<register_spec> ordered_specs;
  ordered_specs.resize(expected_count);
  std::vector<bool> seen(expected_count, false);
  for (const auto& spec : context.register_specs) {
    if (spec.reg_id >= expected_count) {
      error = "register id out of range";
      return false;
    }
    if (seen[spec.reg_id]) {
      error = "duplicate register id";
      return false;
    }
    seen[spec.reg_id] = true;
    ordered_specs[spec.reg_id] = spec;
  }
  context.register_specs = std::move(ordered_specs);
  context.register_names.clear();
  context.register_names.reserve(context.register_specs.size());
  for (const auto& spec : context.register_specs) {
    context.register_names.push_back(spec.name);
  }

  context.modules_by_id.clear();
  context.modules_by_id.reserve(context.modules.size());
  for (const auto& module : context.modules) {
    context.modules_by_id[module.id] = module;
  }

  context.threads.reserve(thread_map.size());
  for (const auto& [_, info] : thread_map) {
    context.threads.push_back(info);
  }
  std::sort(
      context.threads.begin(),
      context.threads.end(),
      [](const replay_thread_info& lhs, const replay_thread_info& rhs) { return lhs.thread_id < rhs.thread_id; }
  );

  if (!context.register_names.empty()) {
    context.sp_reg_id = find_register_with_flag(context.register_specs, register_flag_sp);
    if (!context.sp_reg_id.has_value()) {
      context.sp_reg_id = resolve_stack_reg_id(reader.header().arch, context.register_names);
    }
  }

  out = std::move(context);
  return true;
}

} // namespace w1::rewind
