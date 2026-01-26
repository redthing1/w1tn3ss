#include "replay_checkpoint.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>

#include "w1rewind/format/trace_io.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/mapping_state.hpp"
#include "w1rewind/replay/replay_state_applier.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace w1::rewind {

namespace {

struct thread_build_state {
  uint64_t flow_count = 0;
  uint32_t last_regfile_id = 0;
  replay_state state{};
  bool initialized = false;
  std::vector<replay_checkpoint_entry> entries;
};

bool write_string(std::ostream& out, const std::string& value) {
  uint32_t size = static_cast<uint32_t>(value.size());
  if (!write_stream_u32(out, size)) {
    return false;
  }
  if (size == 0) {
    return true;
  }
  return write_stream_bytes(out, value.data(), value.size());
}

bool read_string(std::istream& in, std::string& out) {
  uint32_t size = 0;
  if (!read_stream_u32(in, size)) {
    return false;
  }
  if (size == 0) {
    out.clear();
    return true;
  }
  if (size > static_cast<uint32_t>(std::numeric_limits<size_t>::max())) {
    return false;
  }
  out.resize(size);
  return read_stream_bytes(in, out.data(), out.size());
}

bool write_reg_write_entry(std::ostream& out, const reg_write_entry& entry) {
  uint8_t kind = static_cast<uint8_t>(entry.ref_kind);
  if (!write_stream_bytes(out, &kind, sizeof(kind))) {
    return false;
  }
  uint8_t reserved = entry.reserved;
  if (!write_stream_bytes(out, &reserved, sizeof(reserved))) {
    return false;
  }
  if (!write_stream_u32(out, entry.byte_offset) || !write_stream_u32(out, entry.byte_size) ||
      !write_stream_u32(out, entry.reg_id)) {
    return false;
  }
  if (!write_string(out, entry.reg_name)) {
    return false;
  }
  uint32_t value_size = static_cast<uint32_t>(entry.value.size());
  if (!write_stream_u32(out, value_size)) {
    return false;
  }
  if (value_size == 0) {
    return true;
  }
  return write_stream_bytes(out, entry.value.data(), entry.value.size());
}

bool read_reg_write_entry(std::istream& in, reg_write_entry& entry) {
  uint8_t kind = 0;
  uint8_t reserved = 0;
  if (!read_stream_bytes(in, &kind, sizeof(kind)) || !read_stream_bytes(in, &reserved, sizeof(reserved))) {
    return false;
  }
  entry.ref_kind = static_cast<reg_ref_kind>(kind);
  entry.reserved = reserved;
  if (!read_stream_u32(in, entry.byte_offset) || !read_stream_u32(in, entry.byte_size) ||
      !read_stream_u32(in, entry.reg_id)) {
    return false;
  }
  if (!read_string(in, entry.reg_name)) {
    return false;
  }
  uint32_t value_size = 0;
  if (!read_stream_u32(in, value_size)) {
    return false;
  }
  if (value_size > static_cast<uint32_t>(std::numeric_limits<size_t>::max())) {
    return false;
  }
  entry.value.resize(value_size);
  if (value_size == 0) {
    return true;
  }
  return read_stream_bytes(in, entry.value.data(), entry.value.size());
}

bool write_memory_segment(std::ostream& out, const memory_segment& segment) {
  if (!write_stream_u32(out, segment.space_id) || !write_stream_u64(out, segment.base)) {
    return false;
  }
  uint64_t size = static_cast<uint64_t>(segment.bytes.size());
  if (!write_stream_u64(out, size)) {
    return false;
  }
  if (size == 0) {
    return true;
  }
  return write_stream_bytes(out, segment.bytes.data(), segment.bytes.size());
}

bool read_memory_segment(std::istream& in, memory_segment& segment) {
  if (!read_stream_u32(in, segment.space_id) || !read_stream_u64(in, segment.base)) {
    return false;
  }
  uint64_t size = 0;
  if (!read_stream_u64(in, size)) {
    return false;
  }
  if (size > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
    return false;
  }
  segment.bytes.resize(static_cast<size_t>(size));
  if (size == 0) {
    return true;
  }
  return read_stream_bytes(in, segment.bytes.data(), segment.bytes.size());
}

bool write_mapping_record(std::ostream& out, const mapping_record& record) {
  uint8_t kind = static_cast<uint8_t>(record.kind);
  uint8_t perms = static_cast<uint8_t>(record.perms);
  uint8_t flags = record.flags;
  if (!write_stream_bytes(out, &kind, sizeof(kind)) || !write_stream_u32(out, record.space_id) ||
      !write_stream_u64(out, record.base) || !write_stream_u64(out, record.size) ||
      !write_stream_bytes(out, &perms, sizeof(perms)) || !write_stream_bytes(out, &flags, sizeof(flags)) ||
      !write_stream_u64(out, record.image_id) || !write_stream_u64(out, record.image_offset)) {
    return false;
  }
  return write_string(out, record.name);
}

bool read_mapping_record(std::istream& in, mapping_record& record) {
  uint8_t kind = 0;
  uint8_t perms = 0;
  uint8_t flags = 0;
  if (!read_stream_bytes(in, &kind, sizeof(kind)) || !read_stream_u32(in, record.space_id) ||
      !read_stream_u64(in, record.base) || !read_stream_u64(in, record.size) ||
      !read_stream_bytes(in, &perms, sizeof(perms)) || !read_stream_bytes(in, &flags, sizeof(flags)) ||
      !read_stream_u64(in, record.image_id) || !read_stream_u64(in, record.image_offset)) {
    return false;
  }
  record.kind = static_cast<mapping_event_kind>(kind);
  record.perms = static_cast<mapping_perm>(perms);
  record.flags = flags;
  return read_string(in, record.name);
}

bool snapshot_entry(
    uint64_t thread_id, uint64_t sequence, const trace_record_location& location, uint32_t regfile_id,
    const replay_state& state, const mapping_state* mappings, bool include_memory, replay_checkpoint_entry& entry,
    std::string& error
) {
  entry = replay_checkpoint_entry{};
  entry.thread_id = thread_id;
  entry.sequence = sequence;
  entry.location = location;
  entry.regfile_id = regfile_id;
  entry.registers = state.collect_register_writes(regfile_id);

  if (include_memory) {
    auto spans = state.memory_store().spans();
    entry.memory_segments.reserve(spans.size());
    for (const auto& span : spans) {
      memory_segment segment{};
      segment.space_id = span.space_id;
      segment.base = span.base;
      segment.bytes = span.bytes;
      entry.memory_segments.push_back(std::move(segment));
    }
  }

  if (mappings) {
    if (!mappings->snapshot(entry.mappings, error)) {
      if (error.empty()) {
        error = "failed to snapshot mappings";
      }
      return false;
    }
  }

  return true;
}

bool write_checkpoint_header(std::ostream& out, const replay_checkpoint_header& header) {
  if (!write_stream_bytes(out, k_trace_checkpoint_magic.data(), k_trace_checkpoint_magic.size())) {
    return false;
  }
  return write_stream_u16(out, header.version) && write_stream_u16(out, header.header_size) &&
         write_stream_bytes(out, header.trace_uuid.data(), header.trace_uuid.size()) &&
         write_stream_u32(out, header.flags) && write_stream_u32(out, header.stride) &&
         write_stream_u32(out, header.thread_count) && write_stream_u32(out, header.entry_count);
}

bool read_checkpoint_header(std::istream& in, replay_checkpoint_header& header) {
  std::array<uint8_t, 8> magic{};
  if (!read_stream_bytes(in, magic.data(), magic.size())) {
    return false;
  }
  if (std::memcmp(magic.data(), k_trace_checkpoint_magic.data(), k_trace_checkpoint_magic.size()) != 0) {
    return false;
  }
  return read_stream_u16(in, header.version) && read_stream_u16(in, header.header_size) &&
         read_stream_bytes(in, header.trace_uuid.data(), header.trace_uuid.size()) &&
         read_stream_u32(in, header.flags) && read_stream_u32(in, header.stride) &&
         read_stream_u32(in, header.thread_count) && read_stream_u32(in, header.entry_count);
}

} // namespace

const replay_checkpoint_entry* replay_checkpoint_index::find_checkpoint(uint64_t thread_id, uint64_t sequence) const {
  auto thread_it = std::lower_bound(
      threads.begin(), threads.end(), thread_id,
      [](const replay_checkpoint_thread_index& entry, uint64_t value) { return entry.thread_id < value; }
  );
  if (thread_it == threads.end() || thread_it->thread_id != thread_id) {
    return nullptr;
  }
  if (thread_it->entry_count == 0) {
    return nullptr;
  }

  auto begin =
      entries.begin() + static_cast<std::vector<replay_checkpoint_entry>::difference_type>(thread_it->entry_start);
  auto end = begin + static_cast<std::vector<replay_checkpoint_entry>::difference_type>(thread_it->entry_count);
  auto it = std::lower_bound(begin, end, sequence, [](const replay_checkpoint_entry& entry, uint64_t value) {
    return entry.sequence < value;
  });
  if (it == begin) {
    if (it->sequence > sequence) {
      return nullptr;
    }
    return &(*it);
  }
  if (it == end) {
    return &(*(end - 1));
  }
  if (it->sequence == sequence) {
    return &(*it);
  }
  return &(*(it - 1));
}

std::string default_replay_checkpoint_path(const std::string& trace_path) { return trace_path + ".w1rchk"; }

bool build_replay_checkpoint(const replay_checkpoint_config& config, replay_checkpoint_index* out, std::string& error) {
  error.clear();
  if (!out) {
    error = "checkpoint output required";
    return false;
  }
  if (config.trace_path.empty()) {
    error = "trace path required";
    return false;
  }
  if (config.stride == 0) {
    error = "checkpoint stride must be non-zero";
    return false;
  }

  std::string output_path =
      config.output_path.empty() ? default_replay_checkpoint_path(config.trace_path) : config.output_path;

  trace_reader reader(config.trace_path);
  if (!reader.open()) {
    error = reader.error().empty() ? "failed to open trace" : std::string(reader.error());
    return false;
  }

  replay_context context;
  if (!load_replay_context(config.trace_path, context, error)) {
    return false;
  }

  bool use_blocks = context.features.has_block_exec && !context.blocks_by_id.empty();
  bool use_instructions = context.features.has_flow_instruction;
  if (!use_blocks && !use_instructions) {
    error = "trace has no flow records";
    return false;
  }

  std::map<uint64_t, thread_build_state> threads;
  replay_state_applier applier(context);
  mapping_state mapping_snapshot;
  std::string mapping_error;
  if (!mapping_snapshot.reset(context.mappings, mapping_error)) {
    error = mapping_error.empty() ? "invalid mapping snapshot" : mapping_error;
    return false;
  }
  bool include_mappings = context.features.has_mapping_events;

  trace_record record;
  trace_record_location location{};
  while (reader.read_next(record, &location)) {
    if (std::holds_alternative<mapping_record>(record)) {
      if (include_mappings) {
        std::string mapping_error;
        if (!mapping_snapshot.apply_event(std::get<mapping_record>(record), mapping_error)) {
          error = mapping_error.empty() ? "failed to apply mapping event" : mapping_error;
          return false;
        }
      }
      continue;
    }

    if (std::holds_alternative<reg_write_record>(record)) {
      const auto& write = std::get<reg_write_record>(record);
      if (config.thread_id != 0 && write.thread_id != config.thread_id) {
        continue;
      }
      auto& state = threads[write.thread_id];
      if (!state.initialized) {
        state.state.set_register_files(context.register_files);
        state.initialized = true;
      }
      state.last_regfile_id = write.regfile_id;
      std::string apply_error;
      if (!applier.apply_reg_write(write, write.thread_id, true, state.state, apply_error)) {
        error = apply_error.empty() ? "failed to apply register write" : apply_error;
        return false;
      }
      continue;
    }

    if (std::holds_alternative<mem_access_record>(record)) {
      if (!config.include_memory) {
        continue;
      }
      const auto& access = std::get<mem_access_record>(record);
      if (config.thread_id != 0 && access.thread_id != config.thread_id) {
        continue;
      }
      auto& state = threads[access.thread_id];
      if (!state.initialized) {
        state.state.set_register_files(context.register_files);
        state.initialized = true;
      }
      applier.apply_memory_access(access, access.thread_id, true, state.state);
      continue;
    }

    if (std::holds_alternative<snapshot_record>(record)) {
      const auto& snapshot = std::get<snapshot_record>(record);
      if (config.thread_id != 0 && snapshot.thread_id != config.thread_id) {
        continue;
      }
      auto& state = threads[snapshot.thread_id];
      if (!state.initialized) {
        state.state.set_register_files(context.register_files);
        state.initialized = true;
      }
      state.last_regfile_id = snapshot.regfile_id;
      std::string apply_error;
      if (!applier.apply_snapshot(
              snapshot, snapshot.thread_id, true, config.include_memory, state.state, apply_error
          )) {
        error = apply_error.empty() ? "failed to apply snapshot" : apply_error;
        return false;
      }
      continue;
    }

    if (use_blocks) {
      if (const auto* exec = std::get_if<block_exec_record>(&record)) {
        if (config.thread_id != 0 && exec->thread_id != config.thread_id) {
          continue;
        }
        auto& state = threads[exec->thread_id];
        if (!state.initialized) {
          state.state.set_register_files(context.register_files);
          state.initialized = true;
        }
        if (state.flow_count % config.stride == 0) {
          replay_checkpoint_entry entry{};
          std::string snapshot_error;
          if (!snapshot_entry(
                  exec->thread_id, exec->sequence, location, state.last_regfile_id, state.state,
                  include_mappings ? &mapping_snapshot : nullptr, config.include_memory, entry, snapshot_error
              )) {
            error = snapshot_error.empty() ? "failed to capture checkpoint" : snapshot_error;
            return false;
          }
          state.entries.push_back(std::move(entry));
        }
        state.flow_count += 1;
      }
      continue;
    }

    if (const auto* inst = std::get_if<flow_instruction_record>(&record)) {
      if (config.thread_id != 0 && inst->thread_id != config.thread_id) {
        continue;
      }
      auto& state = threads[inst->thread_id];
      if (!state.initialized) {
        state.state.set_register_files(context.register_files);
        state.initialized = true;
      }
      if (state.flow_count % config.stride == 0) {
        replay_checkpoint_entry entry{};
        std::string snapshot_error;
        if (!snapshot_entry(
                inst->thread_id, inst->sequence, location, state.last_regfile_id, state.state,
                include_mappings ? &mapping_snapshot : nullptr, config.include_memory, entry, snapshot_error
            )) {
          error = snapshot_error.empty() ? "failed to capture checkpoint" : snapshot_error;
          return false;
        }
        state.entries.push_back(std::move(entry));
      }
      state.flow_count += 1;
    }
  }

  if (!reader.error().empty()) {
    error = reader.error();
    return false;
  }

  replay_checkpoint_index index;
  index.header.version = k_trace_checkpoint_version;
  index.header.header_size = static_cast<uint16_t>(sizeof(replay_checkpoint_header));
  index.header.trace_uuid = context.header.trace_uuid;
  index.header.flags = include_mappings ? k_checkpoint_flag_has_mappings : 0;
  index.header.stride = config.stride;

  std::vector<uint64_t> thread_ids;
  thread_ids.reserve(threads.size());
  for (const auto& [thread_id, _] : threads) {
    thread_ids.push_back(thread_id);
  }
  std::sort(thread_ids.begin(), thread_ids.end());

  for (uint64_t thread_id : thread_ids) {
    auto& state = threads[thread_id];
    if (state.entries.empty()) {
      continue;
    }
    replay_checkpoint_thread_index entry{};
    entry.thread_id = thread_id;
    entry.entry_start = static_cast<uint32_t>(index.entries.size());
    entry.entry_count = static_cast<uint32_t>(state.entries.size());
    index.entries.insert(index.entries.end(), state.entries.begin(), state.entries.end());
    index.threads.push_back(entry);
  }

  index.header.thread_count = static_cast<uint32_t>(index.threads.size());
  index.header.entry_count = static_cast<uint32_t>(index.entries.size());

  std::ofstream out_stream(output_path, std::ios::binary | std::ios::out | std::ios::trunc);
  if (!out_stream.is_open()) {
    error = "failed to open checkpoint output";
    return false;
  }

  if (!write_checkpoint_header(out_stream, index.header)) {
    error = "failed to write checkpoint header";
    return false;
  }

  for (const auto& thread : index.threads) {
    if (!write_stream_u64(out_stream, thread.thread_id) || !write_stream_u32(out_stream, thread.entry_start) ||
        !write_stream_u32(out_stream, thread.entry_count)) {
      error = "failed to write checkpoint thread index";
      return false;
    }
  }

  for (const auto& entry : index.entries) {
    if (!write_stream_u64(out_stream, entry.thread_id) || !write_stream_u64(out_stream, entry.sequence) ||
        !write_stream_u32(out_stream, entry.location.chunk_index) ||
        !write_stream_u32(out_stream, entry.location.record_offset) ||
        !write_stream_u32(out_stream, entry.regfile_id)) {
      error = "failed to write checkpoint entry header";
      return false;
    }

    uint32_t reg_count = static_cast<uint32_t>(entry.registers.size());
    uint32_t mem_count = static_cast<uint32_t>(entry.memory_segments.size());
    uint32_t map_count = static_cast<uint32_t>(entry.mappings.size());
    if (!write_stream_u32(out_stream, reg_count) || !write_stream_u32(out_stream, mem_count) ||
        !write_stream_u32(out_stream, map_count)) {
      error = "failed to write checkpoint entry counts";
      return false;
    }

    for (const auto& reg : entry.registers) {
      if (!write_reg_write_entry(out_stream, reg)) {
        error = "failed to write checkpoint register entry";
        return false;
      }
    }

    for (const auto& segment : entry.memory_segments) {
      if (!write_memory_segment(out_stream, segment)) {
        error = "failed to write checkpoint memory segment";
        return false;
      }
    }

    for (const auto& mapping : entry.mappings) {
      if (!write_mapping_record(out_stream, mapping)) {
        error = "failed to write checkpoint mapping entry";
        return false;
      }
    }
  }

  if (!out_stream.good()) {
    error = "failed to write checkpoint";
    return false;
  }

  *out = std::move(index);
  return true;
}

bool load_replay_checkpoint(const std::string& path, replay_checkpoint_index& out, std::string& error) {
  error.clear();
  std::ifstream in(path, std::ios::binary | std::ios::in);
  if (!in.is_open()) {
    error = "failed to open checkpoint file";
    return false;
  }

  replay_checkpoint_index index;
  if (!read_checkpoint_header(in, index.header)) {
    error = "invalid checkpoint header";
    return false;
  }
  if (index.header.version != k_trace_checkpoint_version) {
    error = "checkpoint version mismatch";
    return false;
  }

  index.threads.resize(index.header.thread_count);
  for (uint32_t i = 0; i < index.header.thread_count; ++i) {
    auto& thread = index.threads[i];
    if (!read_stream_u64(in, thread.thread_id) || !read_stream_u32(in, thread.entry_start) ||
        !read_stream_u32(in, thread.entry_count)) {
      error = "failed to read checkpoint thread index";
      return false;
    }
  }

  index.entries.resize(index.header.entry_count);
  for (uint32_t i = 0; i < index.header.entry_count; ++i) {
    auto& entry = index.entries[i];
    uint32_t reg_count = 0;
    uint32_t mem_count = 0;
    uint32_t map_count = 0;

    if (!read_stream_u64(in, entry.thread_id) || !read_stream_u64(in, entry.sequence) ||
        !read_stream_u32(in, entry.location.chunk_index) || !read_stream_u32(in, entry.location.record_offset) ||
        !read_stream_u32(in, entry.regfile_id) || !read_stream_u32(in, reg_count) || !read_stream_u32(in, mem_count) ||
        !read_stream_u32(in, map_count)) {
      error = "failed to read checkpoint entry header";
      return false;
    }

    entry.registers.resize(reg_count);
    for (uint32_t j = 0; j < reg_count; ++j) {
      if (!read_reg_write_entry(in, entry.registers[j])) {
        error = "failed to read checkpoint register entry";
        return false;
      }
    }

    entry.memory_segments.resize(mem_count);
    for (uint32_t j = 0; j < mem_count; ++j) {
      if (!read_memory_segment(in, entry.memory_segments[j])) {
        error = "failed to read checkpoint memory segment";
        return false;
      }
    }

    entry.mappings.resize(map_count);
    for (uint32_t j = 0; j < map_count; ++j) {
      if (!read_mapping_record(in, entry.mappings[j])) {
        error = "failed to read checkpoint mapping entry";
        return false;
      }
    }
  }

  for (const auto& thread : index.threads) {
    if (thread.entry_start + thread.entry_count > index.entries.size()) {
      error = "checkpoint thread index out of range";
      return false;
    }
  }

  out = std::move(index);
  return true;
}

} // namespace w1::rewind
