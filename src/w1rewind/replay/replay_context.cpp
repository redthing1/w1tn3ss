#include "replay_context.hpp"

#include <algorithm>
#include <limits>

#include "w1rewind/format/register_metadata.hpp"
#include "w1rewind/replay/replay_context_builder.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace w1::rewind {

namespace {

uint64_t safe_end(uint64_t base, uint64_t size) {
  if (size == 0) {
    return base;
  }
  uint64_t end = base + size;
  if (end < base) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

void build_register_file_indexes(replay_context& context) {
  for (auto& entry : context.register_files_by_id) {
    entry.second.id_to_index.clear();
    entry.second.name_to_id.clear();

    if (entry.second.record_index >= context.register_files.size()) {
      continue;
    }
    const auto& record = context.register_files[entry.second.record_index];
    entry.second.id_to_index.reserve(record.registers.size());

    for (size_t i = 0; i < record.registers.size(); ++i) {
      const auto& spec = record.registers[i];
      entry.second.id_to_index.emplace(spec.reg_id, i);
      if (!spec.name.empty()) {
        entry.second.name_to_id.emplace(spec.name, spec.reg_id);
      }
      if (!spec.gdb_name.empty()) {
        entry.second.name_to_id.emplace(spec.gdb_name, spec.reg_id);
      }
    }
  }
}

void build_mapping_ranges(replay_context& context) {
  context.mapping_ranges_by_space.clear();
  for (const auto& mapping : context.mappings) {
    uint64_t end = safe_end(mapping.base, mapping.size);
    if (end <= mapping.base) {
      continue;
    }
    auto& ranges = context.mapping_ranges_by_space[mapping.space_id];
    std::vector<mapping_range> updated;
    updated.reserve(ranges.size() + 1);

    for (const auto& range : ranges) {
      if (range.end <= mapping.base || range.start >= end) {
        updated.push_back(range);
        continue;
      }
      if (range.start < mapping.base) {
        mapping_range left = range;
        left.end = mapping.base;
        if (left.end > left.start) {
          updated.push_back(left);
        }
      }
      if (range.end > end) {
        mapping_range right = range;
        right.start = end;
        if (right.end > right.start) {
          updated.push_back(right);
        }
      }
    }

    mapping_range incoming{};
    incoming.start = mapping.base;
    incoming.end = end;
    incoming.mapping = &mapping;
    updated.push_back(incoming);

    std::sort(updated.begin(), updated.end(), [](const mapping_range& a, const mapping_range& b) {
      return a.start < b.start;
    });
    ranges.swap(updated);
  }
}

bool build_image_blob_indexes(replay_context& context, std::string& error) {
  context.image_blob_indexes_by_id.clear();
  for (const auto& [image_id, blobs] : context.image_blobs_by_id) {
    image_blob_index index{};
    if (!build_image_blob_index(blobs, index, error)) {
      return false;
    }
    if (!index.spans.empty()) {
      context.image_blob_indexes_by_id.emplace(image_id, std::move(index));
    }
  }
  return true;
}

void build_default_registers(replay_context& context) {
  context.default_registers.clear();
  context.default_register_names.clear();
  context.sp_reg_id.reset();
  context.pc_reg_id.reset();
  if (auto* default_file = context.find_register_file(0)) {
    context.default_registers = default_file->registers;
    context.default_register_names.reserve(default_file->registers.size());
    for (const auto& spec : default_file->registers) {
      context.default_register_names.push_back(spec.name);
    }
    context.sp_reg_id = resolve_sp_reg_id(context.default_registers);
    context.pc_reg_id = resolve_pc_reg_id(context.default_registers);
  }
}

} // namespace

const register_file_record* replay_context::find_register_file(uint32_t regfile_id) const {
  auto it = register_files_by_id.find(regfile_id);
  if (it == register_files_by_id.end()) {
    return nullptr;
  }
  if (it->second.record_index >= register_files.size()) {
    return nullptr;
  }
  return &register_files[it->second.record_index];
}

const register_spec* replay_context::find_register_spec(uint32_t regfile_id, uint32_t reg_id) const {
  auto it = register_files_by_id.find(regfile_id);
  if (it == register_files_by_id.end()) {
    return nullptr;
  }
  const auto& index = it->second;
  auto spec_it = index.id_to_index.find(reg_id);
  if (spec_it == index.id_to_index.end()) {
    return nullptr;
  }
  const auto* record = find_register_file(regfile_id);
  if (!record) {
    return nullptr;
  }
  if (spec_it->second >= record->registers.size()) {
    return nullptr;
  }
  return &record->registers[spec_it->second];
}

std::optional<uint32_t> replay_context::resolve_register_id(uint32_t regfile_id, std::string_view name) const {
  auto it = register_files_by_id.find(regfile_id);
  if (it == register_files_by_id.end()) {
    return std::nullopt;
  }
  const auto& index = it->second;
  auto name_it = index.name_to_id.find(std::string(name));
  if (name_it == index.name_to_id.end()) {
    return std::nullopt;
  }
  return name_it->second;
}

const address_space_record* replay_context::find_address_space(uint32_t space_id) const {
  auto it = address_spaces_by_id.find(space_id);
  if (it == address_spaces_by_id.end()) {
    return nullptr;
  }
  if (it->second >= address_spaces.size()) {
    return nullptr;
  }
  return &address_spaces[it->second];
}

const image_record* replay_context::find_image(uint64_t image_id) const {
  auto it = images_by_id.find(image_id);
  if (it == images_by_id.end()) {
    return nullptr;
  }
  if (it->second >= images.size()) {
    return nullptr;
  }
  return &images[it->second];
}

const image_metadata_record* replay_context::find_image_metadata(uint64_t image_id) const {
  auto it = image_metadata_by_id.find(image_id);
  if (it == image_metadata_by_id.end()) {
    return nullptr;
  }
  return &it->second;
}

const mapping_record* replay_context::find_mapping_for_address(
    uint32_t space_id, uint64_t address, uint64_t size, uint64_t& mapping_offset
) const {
  mapping_offset = 0;
  if (size == 0) {
    return nullptr;
  }
  auto it = mapping_ranges_by_space.find(space_id);
  if (it == mapping_ranges_by_space.end() || it->second.empty()) {
    return nullptr;
  }
  const auto& ranges = it->second;
  auto upper = std::upper_bound(ranges.begin(), ranges.end(), address, [](uint64_t value, const mapping_range& range) {
    return value < range.start;
  });
  if (upper == ranges.begin()) {
    return nullptr;
  }
  --upper;
  if (!upper->mapping || address >= upper->end) {
    return nullptr;
  }
  uint64_t address_end = safe_end(address, size);
  if (address_end <= address || address_end > upper->end) {
    return nullptr;
  }
  mapping_offset = address - upper->mapping->base;
  return upper->mapping;
}

const mapping_range* replay_context::find_mapping_after(uint32_t space_id, uint64_t address) const {
  auto it = mapping_ranges_by_space.find(space_id);
  if (it == mapping_ranges_by_space.end() || it->second.empty()) {
    return nullptr;
  }
  const auto& ranges = it->second;
  auto lower = std::lower_bound(ranges.begin(), ranges.end(), address, [](const mapping_range& range, uint64_t value) {
    return range.start < value;
  });
  if (lower == ranges.end()) {
    return nullptr;
  }
  return &(*lower);
}

const image_blob_index* replay_context::find_image_blob_index(uint64_t image_id) const {
  auto it = image_blob_indexes_by_id.find(image_id);
  if (it == image_blob_indexes_by_id.end()) {
    return nullptr;
  }
  return &it->second;
}

bool load_replay_context(const std::string& trace_path, replay_context& out, std::string& error) {
  error.clear();
  trace_reader reader(trace_path);
  if (!reader.open()) {
    error = reader.error().empty() ? "failed to open trace" : std::string(reader.error());
    return false;
  }
  return build_replay_context(reader, out, error);
}

bool validate_replay_context(const replay_context& context, std::string& error) {
  error.clear();

  bool has_uuid = false;
  for (auto byte : context.header.trace_uuid) {
    if (byte != 0) {
      has_uuid = true;
      break;
    }
  }
  if (!has_uuid) {
    error = "trace uuid missing";
    return false;
  }

  if (!context.arch.has_value()) {
    error = "trace missing arch descriptor";
    return false;
  }
  if (!context.environment.has_value()) {
    error = "trace missing environment";
    return false;
  }
  const auto& arch = *context.arch;
  if (arch.arch_id.empty()) {
    error = "arch descriptor missing arch_id";
    return false;
  }
  if (arch.pointer_bits == 0 && arch.address_bits == 0) {
    error = "arch descriptor missing pointer/address size";
    return false;
  }

  if (context.address_spaces.empty()) {
    error = "trace missing address spaces";
    return false;
  }
  for (const auto& space : context.address_spaces) {
    if (space.address_bits == 0) {
      error = "address space missing address_bits";
      return false;
    }
  }

  for (const auto& mapping : context.mappings) {
    if (mapping.size == 0) {
      error = "mapping size is zero";
      return false;
    }
    if (mapping.base + mapping.size < mapping.base) {
      error = "mapping size overflows address space";
      return false;
    }
    if (!context.find_address_space(mapping.space_id)) {
      error = "mapping references unknown address space";
      return false;
    }
    if (mapping.image_id != 0 && !context.find_image(mapping.image_id)) {
      error = "mapping references unknown image";
      return false;
    }
  }

  for (const auto& mapping : context.mapping_events) {
    if (mapping.kind != mapping_event_kind::map && mapping.kind != mapping_event_kind::unmap &&
        mapping.kind != mapping_event_kind::protect) {
      error = "mapping event kind invalid";
      return false;
    }
    if (mapping.size == 0) {
      error = "mapping event size is zero";
      return false;
    }
    if (mapping.base + mapping.size < mapping.base) {
      error = "mapping event size overflows address space";
      return false;
    }
    if (!context.find_address_space(mapping.space_id)) {
      error = "mapping event references unknown address space";
      return false;
    }
    if ((mapping.kind == mapping_event_kind::map || mapping.kind == mapping_event_kind::protect) &&
        mapping.image_id != 0 && !context.find_image(mapping.image_id)) {
      error = "mapping event references unknown image";
      return false;
    }
  }

  for (const auto& [_, ranges] : context.mapping_ranges_by_space) {
    uint64_t prev_end = 0;
    bool has_prev = false;
    for (const auto& range : ranges) {
      if (range.end <= range.start) {
        error = "mapping range invalid";
        return false;
      }
      if (has_prev && range.start < prev_end) {
        error = "mapping ranges overlap";
        return false;
      }
      prev_end = range.end;
      has_prev = true;
    }
  }

  for (const auto& entry : context.image_metadata_by_id) {
    if (!context.find_image(entry.first)) {
      error = "image metadata references unknown image";
      return false;
    }
  }

  for (const auto& entry : context.image_blobs_by_id) {
    if (!context.find_image(entry.first)) {
      error = "image blob references unknown image";
      return false;
    }
  }

  if (!context.register_files.empty()) {
    for (const auto& file : context.register_files) {
      if (file.registers.empty()) {
        error = "register file has no registers";
        return false;
      }
      for (const auto& spec : file.registers) {
        if (spec.bit_size == 0) {
          error = "register spec missing bit_size";
          return false;
        }
      }
    }
  } else if (context.features.has_reg_writes || context.features.has_snapshots) {
    error = "trace missing register files for register data";
    return false;
  }

  return true;
}

bool finalize_replay_context(replay_context& context, std::string& error) {
  error.clear();
  build_register_file_indexes(context);
  build_mapping_ranges(context);
  if (!build_image_blob_indexes(context, error)) {
    return false;
  }
  build_default_registers(context);
  return validate_replay_context(context, error);
}

} // namespace w1::rewind
