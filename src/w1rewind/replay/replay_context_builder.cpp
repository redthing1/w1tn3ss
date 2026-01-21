#include "replay_context_builder.hpp"

#include <algorithm>
#include <unordered_map>

#include "w1rewind/format/register_metadata.hpp"
#include "w1rewind/format/trace_validator.hpp"

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

bool build_replay_context(trace_record_stream& stream, replay_context& out, std::string& error) {
  error.clear();

  replay_context context;
  context.header = stream.header();

  std::unordered_map<uint64_t, replay_thread_info> thread_map;

  trace_record record;
  while (stream.read_next(record, nullptr)) {
    if (std::holds_alternative<target_info_record>(record)) {
      context.target_info = std::get<target_info_record>(record);
    } else if (std::holds_alternative<target_environment_record>(record)) {
      context.target_environment = std::get<target_environment_record>(record);
    } else if (std::holds_alternative<register_spec_record>(record)) {
      context.register_specs = std::get<register_spec_record>(record).registers;
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

  if (!stream.error().empty()) {
    error = std::string(stream.error());
    return false;
  }

  if (!validate_trace_arch(context.header.arch, error)) {
    return false;
  }

  register_spec_validation_options reg_options{};
  reg_options.allow_empty = (context.header.flags & trace_flag_register_deltas) == 0;
  if (!normalize_register_specs(context.register_specs, error, reg_options)) {
    return false;
  }
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
      context.threads.begin(), context.threads.end(),
      [](const replay_thread_info& lhs, const replay_thread_info& rhs) { return lhs.thread_id < rhs.thread_id; }
  );

  if (!context.register_names.empty()) {
    context.sp_reg_id = find_register_with_flag(context.register_specs, register_flag_sp);
    if (!context.sp_reg_id.has_value()) {
      context.sp_reg_id = resolve_sp_reg_id(context.header.arch, context.register_names);
    }
  }

  out = std::move(context);
  return true;
}

} // namespace w1::rewind
