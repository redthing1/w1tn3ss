#include "replay_context.hpp"

#include <algorithm>
#include <unordered_map>

#include "replay_registers.hpp"
#include "trace_reader.hpp"

namespace w1::rewind {

bool replay_context::resolve_address(uint64_t module_id, uint64_t module_offset, uint64_t& address) const {
  if (module_id == 0) {
    address = module_offset;
    return true;
  }
  auto it = modules_by_id.find(module_id);
  if (it == modules_by_id.end()) {
    return false;
  }
  address = it->second.base + module_offset;
  return true;
}

bool replay_context::has_blocks() const { return (header.flags & trace_flag_blocks) != 0; }

bool replay_context::has_registers() const { return !register_names.empty(); }

replay_context::trace_features replay_context::features() const {
  trace_features out{};
  out.has_registers = has_registers();
  out.has_memory_access = (header.flags & trace_flag_memory_access) != 0;
  out.has_memory_values = (header.flags & trace_flag_memory_values) != 0;
  out.has_stack_window = (header.flags & trace_flag_stack_window) != 0;
  out.has_blocks = has_blocks();
  out.track_memory = out.has_registers && ((out.has_memory_access && out.has_memory_values) || out.has_stack_window);
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
    if (std::holds_alternative<register_table_record>(record)) {
      context.register_names = std::get<register_table_record>(record).names;
    } else if (std::holds_alternative<module_table_record>(record)) {
      context.modules = std::get<module_table_record>(record).modules;
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
    context.sp_reg_id = resolve_stack_reg_id(reader.header().architecture, context.register_names);
  }

  out = std::move(context);
  return true;
}

} // namespace w1::rewind
