#include "replay_state.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>

#include "w1rewind/format/register_metadata.hpp"

namespace w1::rewind {

namespace {

uint64_t decode_uint64(std::span<const uint8_t> bytes, endian order) {
  uint64_t value = 0;
  if (order == endian::big) {
    for (uint8_t byte : bytes) {
      value = (value << 8) | static_cast<uint64_t>(byte);
    }
    return value;
  }
  uint64_t shift = 0;
  for (uint8_t byte : bytes) {
    value |= static_cast<uint64_t>(byte) << shift;
    shift += 8;
  }
  return value;
}

} // namespace

void replay_state::reset() {
  banks_.clear();
  memory_.clear();
}

void replay_state::set_register_files(const std::vector<register_file_record>& files) {
  banks_.clear();
  for (const auto& file : files) {
    register_bank bank{};
    bank.slots.reserve(file.registers.size());

    for (const auto& spec : file.registers) {
      register_slot slot{};
      slot.reg_id = spec.reg_id;
      uint32_t size = register_byte_size(spec);
      slot.bytes.resize(size, 0);
      slot.known.resize(size, 0);

      size_t index = bank.slots.size();
      bank.slots.push_back(std::move(slot));

      if (bank.id_to_index.find(spec.reg_id) == bank.id_to_index.end()) {
        bank.id_to_index.emplace(spec.reg_id, index);
      }
      if (!spec.name.empty() && bank.name_to_id.find(spec.name) == bank.name_to_id.end()) {
        bank.name_to_id.emplace(spec.name, spec.reg_id);
      }
      if (!spec.gdb_name.empty() && bank.name_to_id.find(spec.gdb_name) == bank.name_to_id.end()) {
        bank.name_to_id.emplace(spec.gdb_name, spec.reg_id);
      }
    }

    banks_.emplace(file.regfile_id, std::move(bank));
  }
}

replay_state::register_bank* replay_state::find_bank(uint32_t regfile_id) {
  auto it = banks_.find(regfile_id);
  if (it == banks_.end()) {
    return nullptr;
  }
  return &it->second;
}

const replay_state::register_bank* replay_state::find_bank(uint32_t regfile_id) const {
  auto it = banks_.find(regfile_id);
  if (it == banks_.end()) {
    return nullptr;
  }
  return &it->second;
}

void replay_state::reset_register_bank(register_bank& bank) {
  for (auto& slot : bank.slots) {
    std::fill(slot.bytes.begin(), slot.bytes.end(), 0);
    std::fill(slot.known.begin(), slot.known.end(), 0);
  }
}

replay_state::register_slot* replay_state::ensure_slot(register_bank& bank, uint32_t reg_id, uint32_t min_size) {
  auto it = bank.id_to_index.find(reg_id);
  if (it == bank.id_to_index.end()) {
    return nullptr;
  }

  replay_state::register_slot& slot = bank.slots[it->second];
  if (slot.bytes.size() < min_size) {
    slot.bytes.resize(min_size, 0);
    slot.known.resize(min_size, 0);
  }
  return &slot;
}

bool replay_state::apply_reg_write(
    uint32_t regfile_id, const std::vector<reg_write_entry>& entries, std::string& error
) {
  error.clear();
  if (entries.empty()) {
    return true;
  }

  register_bank* bank = find_bank(regfile_id);
  if (!bank) {
    error = "register file missing";
    return false;
  }

  for (const auto& entry : entries) {
    uint32_t reg_id = entry.reg_id;
    if (entry.ref_kind == reg_ref_kind::reg_name) {
      if (entry.reg_name.empty()) {
        error = "register name missing";
        return false;
      }
      auto it = bank->name_to_id.find(entry.reg_name);
      if (it == bank->name_to_id.end()) {
        error = "unknown register name: " + entry.reg_name;
        return false;
      }
      reg_id = it->second;
    } else if (bank->id_to_index.find(reg_id) == bank->id_to_index.end()) {
      error = "unknown register id";
      return false;
    }

    uint32_t write_size = entry.byte_size;
    if (write_size == 0) {
      write_size = static_cast<uint32_t>(entry.value.size());
    }
    write_size = std::min(write_size, static_cast<uint32_t>(entry.value.size()));
    if (write_size == 0) {
      continue;
    }

    uint32_t required_size = entry.byte_offset + write_size;
    register_slot* slot = ensure_slot(*bank, reg_id, required_size);
    if (!slot || slot->bytes.empty()) {
      error = "register slot missing";
      return false;
    }

    uint32_t copy_size = std::min<uint32_t>(write_size, static_cast<uint32_t>(slot->bytes.size() - entry.byte_offset));
    if (copy_size == 0) {
      continue;
    }

    std::memcpy(slot->bytes.data() + entry.byte_offset, entry.value.data(), copy_size);
    std::fill(
        slot->known.begin() + static_cast<std::ptrdiff_t>(entry.byte_offset),
        slot->known.begin() + static_cast<std::ptrdiff_t>(entry.byte_offset + copy_size), 1
    );
  }

  return true;
}

bool replay_state::apply_register_snapshot(
    uint32_t regfile_id, const std::vector<reg_write_entry>& entries, std::string& error
) {
  register_bank* bank = find_bank(regfile_id);
  if (!bank) {
    error = "register file missing";
    return false;
  }
  reset_register_bank(*bank);
  return apply_reg_write(regfile_id, entries, error);
}

std::optional<uint64_t> replay_state::register_value(uint32_t regfile_id, uint32_t reg_id, endian byte_order) const {
  const register_bank* bank = find_bank(regfile_id);
  if (!bank) {
    return std::nullopt;
  }
  auto it = bank->id_to_index.find(reg_id);
  if (it == bank->id_to_index.end()) {
    return std::nullopt;
  }

  const register_slot& slot = bank->slots[it->second];
  if (slot.bytes.empty() || slot.bytes.size() > sizeof(uint64_t)) {
    return std::nullopt;
  }

  for (size_t i = 0; i < slot.known.size(); ++i) {
    if (slot.known[i] == 0) {
      return std::nullopt;
    }
  }

  return decode_uint64(slot.bytes, byte_order);
}

bool replay_state::copy_register_bytes(
    uint32_t regfile_id, uint32_t reg_id, std::span<std::byte> out, bool& known
) const {
  const register_bank* bank = find_bank(regfile_id);
  if (!bank) {
    return false;
  }
  auto it = bank->id_to_index.find(reg_id);
  if (it == bank->id_to_index.end()) {
    return false;
  }

  const register_slot& slot = bank->slots[it->second];
  if (out.size() < slot.bytes.size()) {
    return false;
  }

  known = true;
  for (size_t i = 0; i < slot.bytes.size(); ++i) {
    if (i < slot.known.size() && slot.known[i] != 0) {
      out[i] = std::byte{slot.bytes[i]};
    } else {
      out[i] = std::byte{0};
      known = false;
    }
  }

  return true;
}

std::vector<reg_write_entry> replay_state::collect_register_writes(uint32_t regfile_id) const {
  std::vector<reg_write_entry> out;
  const register_bank* bank = find_bank(regfile_id);
  if (!bank) {
    return out;
  }

  for (const auto& slot : bank->slots) {
    if (slot.bytes.empty() || slot.known.empty()) {
      continue;
    }

    size_t size = slot.bytes.size();
    size_t offset = 0;
    while (offset < size) {
      while (offset < size && slot.known[offset] == 0) {
        ++offset;
      }
      if (offset >= size) {
        break;
      }
      size_t start = offset;
      while (offset < size && slot.known[offset] != 0) {
        ++offset;
      }
      size_t length = offset - start;
      if (length == 0) {
        continue;
      }

      reg_write_entry entry{};
      entry.ref_kind = reg_ref_kind::reg_id;
      entry.byte_offset = static_cast<uint32_t>(start);
      entry.byte_size = static_cast<uint32_t>(length);
      entry.reg_id = slot.reg_id;
      entry.value.insert(
          entry.value.end(), slot.bytes.begin() + static_cast<std::ptrdiff_t>(start),
          slot.bytes.begin() + static_cast<std::ptrdiff_t>(start + length)
      );
      out.push_back(std::move(entry));
    }
  }

  return out;
}

void replay_state::set_memory_segments(std::span<const memory_segment> segments) {
  memory_.clear();
  std::vector<memory_segment> owned(segments.begin(), segments.end());
  apply_memory_segments(owned);
}

void replay_state::apply_memory_bytes(uint32_t space_id, uint64_t address, std::span<const uint8_t> data) {
  memory_.apply_bytes(space_id, address, data);
}

void replay_state::apply_memory_segments(const std::vector<memory_segment>& segments) {
  std::vector<memory_span> spans;
  spans.reserve(segments.size());
  for (const auto& segment : segments) {
    memory_span span{};
    span.space_id = segment.space_id;
    span.base = segment.base;
    span.bytes = segment.bytes;
    spans.push_back(std::move(span));
  }
  memory_.apply_segments(spans);
}

memory_read replay_state::read_memory(uint32_t space_id, uint64_t address, size_t size) const {
  return memory_.read(space_id, address, size);
}

} // namespace w1::rewind
