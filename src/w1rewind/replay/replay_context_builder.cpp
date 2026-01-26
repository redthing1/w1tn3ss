#include "replay_context_builder.hpp"

#include <algorithm>
#include <limits>
#include <unordered_map>

#include "mapping_state.hpp"
namespace w1::rewind {

namespace {

void upsert_address_space(replay_context& context, address_space_record record) {
  auto it = context.address_spaces_by_id.find(record.space_id);
  if (it != context.address_spaces_by_id.end() && it->second < context.address_spaces.size()) {
    context.address_spaces[it->second] = std::move(record);
    return;
  }
  size_t index = context.address_spaces.size();
  context.address_spaces.push_back(std::move(record));
  context.address_spaces_by_id[context.address_spaces.back().space_id] = index;
}

void upsert_register_file(replay_context& context, register_file_record record) {
  auto it = context.register_files_by_id.find(record.regfile_id);
  if (it != context.register_files_by_id.end() && it->second.record_index < context.register_files.size()) {
    context.register_files[it->second.record_index] = std::move(record);
    return;
  }
  size_t index = context.register_files.size();
  context.register_files.push_back(std::move(record));
  register_file_index index_entry{};
  index_entry.record_index = index;
  context.register_files_by_id[context.register_files.back().regfile_id] = std::move(index_entry);
}

void upsert_image(replay_context& context, image_record record) {
  auto it = context.images_by_id.find(record.image_id);
  if (it != context.images_by_id.end() && it->second < context.images.size()) {
    context.images[it->second] = std::move(record);
    return;
  }
  size_t index = context.images.size();
  context.images.push_back(std::move(record));
  context.images_by_id[context.images.back().image_id] = index;
}

} // namespace

bool build_replay_context(trace_record_stream& stream, replay_context& out, std::string& error) {
  error.clear();

  replay_context context;
  context.header = stream.header();

  std::unordered_map<uint64_t, replay_thread_info> thread_map;

  trace_record record;
  bool seen_flow = false;
  mapping_state preflow_mappings;
  while (stream.read_next(record, nullptr)) {
    if (std::holds_alternative<arch_descriptor_record>(record)) {
      context.arch = std::get<arch_descriptor_record>(record);
    } else if (std::holds_alternative<environment_record>(record)) {
      context.environment = std::get<environment_record>(record);
    } else if (std::holds_alternative<address_space_record>(record)) {
      upsert_address_space(context, std::get<address_space_record>(record));
    } else if (std::holds_alternative<register_file_record>(record)) {
      upsert_register_file(context, std::get<register_file_record>(record));
    } else if (std::holds_alternative<image_record>(record)) {
      upsert_image(context, std::get<image_record>(record));
    } else if (std::holds_alternative<image_metadata_record>(record)) {
      const auto& meta = std::get<image_metadata_record>(record);
      context.image_metadata_by_id[meta.image_id] = meta;
      context.features.has_image_metadata = true;
    } else if (std::holds_alternative<image_blob_record>(record)) {
      const auto& blob = std::get<image_blob_record>(record);
      context.image_blobs_by_id[blob.image_id].push_back(blob);
      context.features.has_image_blobs = true;
    } else if (std::holds_alternative<mapping_record>(record)) {
      const auto& mapping = std::get<mapping_record>(record);
      if (!seen_flow) {
        std::string mapping_error;
        if (!preflow_mappings.apply_event(mapping, mapping_error)) {
          error = mapping_error.empty() ? "invalid mapping record" : mapping_error;
          return false;
        }
      } else {
        context.mapping_events.push_back(mapping);
        context.features.has_mapping_events = true;
      }
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
    } else if (std::holds_alternative<flow_instruction_record>(record)) {
      context.features.has_flow_instruction = true;
      seen_flow = true;
    } else if (std::holds_alternative<block_exec_record>(record)) {
      context.features.has_block_exec = true;
      seen_flow = true;
    } else if (std::holds_alternative<reg_write_record>(record)) {
      context.features.has_reg_writes = true;
    } else if (std::holds_alternative<mem_access_record>(record)) {
      context.features.has_mem_access = true;
    } else if (std::holds_alternative<snapshot_record>(record)) {
      context.features.has_snapshots = true;
    }
  }

  if (!stream.error().empty()) {
    error = std::string(stream.error());
    return false;
  }

  if (!preflow_mappings.snapshot(context.mappings, error)) {
    return false;
  }

  context.threads.reserve(thread_map.size());
  for (const auto& [_, info] : thread_map) {
    context.threads.push_back(info);
  }
  std::sort(
      context.threads.begin(), context.threads.end(),
      [](const replay_thread_info& lhs, const replay_thread_info& rhs) { return lhs.thread_id < rhs.thread_id; }
  );

  if (!finalize_replay_context(context, error)) {
    return false;
  }

  out = std::move(context);
  return true;
}

} // namespace w1::rewind
