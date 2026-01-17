#include "replay_checkpoint.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>

#include "trace_io.hpp"
#include "replay_context.hpp"
#include "replay_state_applier.hpp"

namespace w1::rewind {

namespace {

struct thread_build_state {
  uint64_t flow_count = 0;
  replay_state state{};
  std::vector<replay_checkpoint_entry> entries;
};

bool record_is_flow(const trace_record& record, bool use_blocks, uint64_t& sequence, uint64_t& thread_id) {
  if (use_blocks && std::holds_alternative<block_exec_record>(record)) {
    const auto& exec = std::get<block_exec_record>(record);
    sequence = exec.sequence;
    thread_id = exec.thread_id;
    return true;
  }
  if (!use_blocks && std::holds_alternative<instruction_record>(record)) {
    const auto& inst = std::get<instruction_record>(record);
    sequence = inst.sequence;
    thread_id = inst.thread_id;
    return true;
  }
  return false;
}

replay_checkpoint_entry snapshot_entry(
    uint64_t thread_id,
    uint64_t sequence,
    const trace_record_location& location,
    const replay_state& state,
    bool include_memory
) {
  replay_checkpoint_entry entry{};
  entry.thread_id = thread_id;
  entry.sequence = sequence;
  entry.location = location;

  const auto& regs = state.registers();
  entry.registers.reserve(regs.size());
  for (size_t i = 0; i < regs.size(); ++i) {
    if (!regs[i].has_value()) {
      continue;
    }
    register_delta delta{};
    delta.reg_id = static_cast<uint16_t>(i);
    delta.value = *regs[i];
    entry.registers.push_back(delta);
  }

  if (include_memory) {
    const auto& memory = state.memory_map();
    entry.memory.reserve(memory.size());
    for (const auto& [address, value] : memory) {
      entry.memory.emplace_back(address, value);
    }
    std::sort(entry.memory.begin(), entry.memory.end(), [](const auto& lhs, const auto& rhs) {
      return lhs.first < rhs.first;
    });
  }

  return entry;
}

 

bool write_checkpoint_header(
    std::ostream& out,
    const replay_checkpoint_header& header,
    uint32_t thread_count,
    uint32_t entry_count
) {
  if (!write_stream_bytes(out, k_replay_checkpoint_magic.data(), k_replay_checkpoint_magic.size())) {
    return false;
  }
  return write_stream_u16(out, header.version) && write_stream_u16(out, header.trace_version) &&
         write_stream_u16(out, static_cast<uint16_t>(header.architecture)) &&
         write_stream_u32(out, header.pointer_size) && write_stream_u64(out, header.trace_flags) &&
         write_stream_u32(out, header.register_count) && write_stream_u32(out, header.stride) &&
         write_stream_u32(out, thread_count) && write_stream_u32(out, entry_count);
}

bool read_checkpoint_header(
    std::istream& in,
    replay_checkpoint_header& header,
    uint32_t& thread_count,
    uint32_t& entry_count
) {
  std::array<uint8_t, 8> magic{};
  if (!read_stream_bytes(in, magic.data(), magic.size())) {
    return false;
  }
  if (std::memcmp(magic.data(), k_replay_checkpoint_magic.data(), k_replay_checkpoint_magic.size()) != 0) {
    return false;
  }

  uint16_t arch = 0;
  if (!read_stream_u16(in, header.version) || !read_stream_u16(in, header.trace_version) || !read_stream_u16(in, arch) ||
      !read_stream_u32(in, header.pointer_size) || !read_stream_u64(in, header.trace_flags) ||
      !read_stream_u32(in, header.register_count) || !read_stream_u32(in, header.stride) ||
      !read_stream_u32(in, thread_count) || !read_stream_u32(in, entry_count)) {
    return false;
  }

  header.architecture = static_cast<trace_arch>(arch);
  return true;
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

  auto begin = entries.begin() + static_cast<std::vector<replay_checkpoint_entry>::difference_type>(thread_it->entry_start);
  auto end = begin + static_cast<std::vector<replay_checkpoint_entry>::difference_type>(thread_it->entry_count);
  auto it = std::lower_bound(
      begin, end, sequence,
      [](const replay_checkpoint_entry& entry, uint64_t value) { return entry.sequence < value; }
  );
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

std::string default_replay_checkpoint_path(const std::string& trace_path) {
  return trace_path + ".w1rchk";
}

bool build_replay_checkpoint(
    const replay_checkpoint_config& config,
    replay_checkpoint_index* out,
    std::string& error
) {
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

  std::string output_path = config.output_path.empty() ? default_replay_checkpoint_path(config.trace_path)
                                                       : config.output_path;

  trace_reader reader(config.trace_path);
  if (!reader.open()) {
    error = reader.error().empty() ? "failed to open trace" : reader.error();
    return false;
  }

  replay_context context;
  if (!load_replay_context(config.trace_path, context, error)) {
    return false;
  }

  bool use_blocks = (reader.header().flags & trace_flag_blocks) != 0;
  bool use_instructions = (reader.header().flags & trace_flag_instructions) != 0;
  if (use_blocks == use_instructions) {
    error = "trace has unsupported flow flags";
    return false;
  }

  uint32_t max_register_id = 0;
  bool have_register_table = !context.register_names.empty();
  bool have_registers = false;

  std::map<uint64_t, thread_build_state> threads;
  replay_state_applier applier(context);

  trace_record record;
  trace_record_location location{};
  while (reader.read_next(record, &location)) {
    if (std::holds_alternative<register_delta_record>(record)) {
      const auto& deltas = std::get<register_delta_record>(record);
      if (config.thread_id != 0 && deltas.thread_id != config.thread_id) {
        continue;
      }
      auto& state = threads[deltas.thread_id];
      applier.apply_register_deltas(deltas, deltas.thread_id, true, state.state);
      for (const auto& delta : deltas.deltas) {
        max_register_id = std::max(max_register_id, static_cast<uint32_t>(delta.reg_id));
        have_registers = true;
      }
      continue;
    }

    if (std::holds_alternative<memory_access_record>(record)) {
      if (!config.include_memory) {
        continue;
      }
      const auto& access = std::get<memory_access_record>(record);
      if (config.thread_id != 0 && access.thread_id != config.thread_id) {
        continue;
      }
      auto& state = threads[access.thread_id];
      applier.apply_memory_access(access, access.thread_id, config.include_memory, state.state);
      continue;
    }

    if (std::holds_alternative<boundary_record>(record)) {
      const auto& boundary = std::get<boundary_record>(record);
      if (config.thread_id != 0 && boundary.thread_id != config.thread_id) {
        continue;
      }
      auto& state = threads[boundary.thread_id];
      applier.apply_boundary(boundary, boundary.thread_id, true, config.include_memory, state.state);
      for (const auto& delta : boundary.registers) {
        max_register_id = std::max(max_register_id, static_cast<uint32_t>(delta.reg_id));
        have_registers = true;
      }
      continue;
    }

    uint64_t sequence = 0;
    uint64_t thread_id = 0;
    if (!record_is_flow(record, use_blocks, sequence, thread_id)) {
      continue;
    }

    if (config.thread_id != 0 && thread_id != config.thread_id) {
      continue;
    }

    auto& state = threads[thread_id];
    if (state.flow_count % config.stride == 0) {
      state.entries.push_back(snapshot_entry(thread_id, sequence, location, state.state, config.include_memory));
    }
    state.flow_count += 1;
  }

  if (!reader.error().empty()) {
    error = reader.error();
    return false;
  }

  replay_checkpoint_index index;
  index.header.trace_version = context.header.version;
  index.header.architecture = context.header.architecture;
  index.header.pointer_size = context.header.pointer_size;
  index.header.trace_flags = context.header.flags;
  index.header.stride = config.stride;

  if (have_register_table) {
    index.header.register_count = static_cast<uint32_t>(context.register_names.size());
  } else if (have_registers) {
    index.header.register_count = max_register_id + 1;
  }

  for (const auto& [thread_id, state] : threads) {
    replay_checkpoint_thread_index entry{};
    entry.thread_id = thread_id;
    entry.entry_start = static_cast<uint32_t>(index.entries.size());
    entry.entry_count = static_cast<uint32_t>(state.entries.size());
    index.entries.insert(index.entries.end(), state.entries.begin(), state.entries.end());
    index.threads.push_back(entry);
  }

  std::ofstream out_stream(output_path, std::ios::binary | std::ios::out | std::ios::trunc);
  if (!out_stream.is_open()) {
    error = "failed to open checkpoint output";
    return false;
  }

  if (!write_checkpoint_header(
          out_stream,
          index.header,
          static_cast<uint32_t>(index.threads.size()),
          static_cast<uint32_t>(index.entries.size())
      )) {
    error = "failed to write checkpoint header";
    return false;
  }

  for (const auto& thread : index.threads) {
    if (!write_stream_u64(out_stream, thread.thread_id) ||
        !write_stream_u32(out_stream, thread.entry_start) ||
        !write_stream_u32(out_stream, thread.entry_count)) {
      error = "failed to write checkpoint thread index";
      return false;
    }
  }

  for (const auto& entry : index.entries) {
    if (!write_stream_u64(out_stream, entry.thread_id) || !write_stream_u64(out_stream, entry.sequence) ||
        !write_stream_u32(out_stream, entry.location.chunk_index) ||
        !write_stream_u32(out_stream, entry.location.record_offset)) {
      error = "failed to write checkpoint entry header";
      return false;
    }

    uint32_t reg_count = static_cast<uint32_t>(entry.registers.size());
    uint32_t mem_count = static_cast<uint32_t>(entry.memory.size());
    if (!write_stream_u32(out_stream, reg_count) || !write_stream_u32(out_stream, mem_count)) {
      error = "failed to write checkpoint entry counts";
      return false;
    }

    for (const auto& reg : entry.registers) {
      if (!write_stream_u16(out_stream, reg.reg_id) || !write_stream_u64(out_stream, reg.value)) {
        error = "failed to write checkpoint register entry";
        return false;
      }
    }

    for (const auto& mem : entry.memory) {
      if (!write_stream_u64(out_stream, mem.first) || !write_stream_bytes(out_stream, &mem.second, 1)) {
        error = "failed to write checkpoint memory entry";
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
  uint32_t thread_count = 0;
  uint32_t entry_count = 0;
  if (!read_checkpoint_header(in, index.header, thread_count, entry_count)) {
    error = "invalid checkpoint header";
    return false;
  }
  if (index.header.version != k_replay_checkpoint_version) {
    error = "checkpoint version mismatch";
    return false;
  }

  index.threads.resize(thread_count);
  for (uint32_t i = 0; i < thread_count; ++i) {
    auto& thread = index.threads[i];
    if (!read_stream_u64(in, thread.thread_id) || !read_stream_u32(in, thread.entry_start) ||
        !read_stream_u32(in, thread.entry_count)) {
      error = "failed to read checkpoint thread index";
      return false;
    }
  }

  index.entries.resize(entry_count);
  for (uint32_t i = 0; i < entry_count; ++i) {
    auto& entry = index.entries[i];
    uint32_t reg_count = 0;
    uint32_t mem_count = 0;

    if (!read_stream_u64(in, entry.thread_id) || !read_stream_u64(in, entry.sequence) ||
        !read_stream_u32(in, entry.location.chunk_index) || !read_stream_u32(in, entry.location.record_offset) ||
        !read_stream_u32(in, reg_count) || !read_stream_u32(in, mem_count)) {
      error = "failed to read checkpoint entry header";
      return false;
    }

    entry.registers.resize(reg_count);
    for (uint32_t j = 0; j < reg_count; ++j) {
      uint16_t reg_id = 0;
      uint64_t value = 0;
      if (!read_stream_u16(in, reg_id) || !read_stream_u64(in, value)) {
        error = "failed to read checkpoint register entry";
        return false;
      }
      entry.registers[j] = register_delta{reg_id, value};
    }

    entry.memory.resize(mem_count);
    for (uint32_t j = 0; j < mem_count; ++j) {
      uint64_t address = 0;
      uint8_t value = 0;
      if (!read_stream_u64(in, address) || !read_stream_bytes(in, &value, 1)) {
        error = "failed to read checkpoint memory entry";
        return false;
      }
      entry.memory[j] = std::make_pair(address, value);
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
