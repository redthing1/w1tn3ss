#include "replay_state.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>

namespace w1::rewind {

void replay_state::reset() {
  registers_.clear();
  reset_register_bytes();
  memory_.clear();
}

void replay_state::set_register_specs(const std::vector<register_spec>& specs) {
  registers_.assign(specs.size(), std::nullopt);
  register_byte_offsets_.assign(specs.size(), 0);
  register_byte_sizes_.assign(specs.size(), 0);
  register_bytes_known_.assign(specs.size(), 0);
  register_bytes_.clear();

  for (size_t i = 0; i < specs.size(); ++i) {
    const auto& spec = specs[i];
    if (spec.value_kind != register_value_kind::bytes) {
      continue;
    }
    uint32_t size = (spec.bits + 7u) / 8u;
    register_byte_offsets_[i] = static_cast<uint32_t>(register_bytes_.size());
    register_byte_sizes_[i] = static_cast<uint16_t>(size);
    register_bytes_.resize(register_bytes_.size() + size, 0);
  }
}

void replay_state::set_register_count(size_t count) {
  registers_.assign(count, std::nullopt);
  reset_register_bytes();
}

void replay_state::ensure_register_capacity(size_t count) {
  if (registers_.size() < count) {
    registers_.resize(count, std::nullopt);
  }
}

void replay_state::apply_register_snapshot(const std::vector<register_delta>& regs) {
  size_t max_id = 0;
  for (const auto& reg : regs) {
    max_id = std::max(max_id, static_cast<size_t>(reg.reg_id));
  }
  ensure_register_capacity(max_id + 1);
  for (auto& value : registers_) {
    value.reset();
  }
  for (const auto& reg : regs) {
    registers_[reg.reg_id] = reg.value;
  }
}

void replay_state::apply_register_deltas(const std::vector<register_delta>& regs) {
  size_t max_id = 0;
  for (const auto& reg : regs) {
    max_id = std::max(max_id, static_cast<size_t>(reg.reg_id));
  }
  ensure_register_capacity(max_id + 1);
  for (const auto& reg : regs) {
    registers_[reg.reg_id] = reg.value;
  }
}

bool replay_state::apply_register_bytes(
    const std::vector<register_bytes_entry>& entries, const std::vector<uint8_t>& data
) {
  if (entries.empty()) {
    return true;
  }
  if (register_byte_sizes_.empty()) {
    return false;
  }

  for (const auto& entry : entries) {
    if (entry.reg_id >= register_byte_sizes_.size()) {
      return false;
    }
    uint16_t expected = register_byte_sizes_[entry.reg_id];
    if (expected == 0 || entry.size != expected) {
      return false;
    }
    uint64_t end = static_cast<uint64_t>(entry.offset) + static_cast<uint64_t>(entry.size);
    if (end > data.size()) {
      return false;
    }
  }

  for (const auto& entry : entries) {
    uint32_t offset = register_byte_offsets_[entry.reg_id];
    uint16_t size = entry.size;
    std::memcpy(register_bytes_.data() + offset, data.data() + entry.offset, size);
    register_bytes_known_[entry.reg_id] = 1;
  }
  return true;
}

void replay_state::collect_register_bytes(
    std::vector<register_bytes_entry>& entries, std::vector<uint8_t>& data
) const {
  entries.clear();
  data.clear();
  if (register_byte_sizes_.empty()) {
    return;
  }

  size_t total = 0;
  size_t count = 0;
  for (size_t i = 0; i < register_byte_sizes_.size(); ++i) {
    uint16_t size = register_byte_sizes_[i];
    if (size == 0 || register_bytes_known_[i] == 0) {
      continue;
    }
    total += size;
    count += 1;
  }

  if (count == 0) {
    return;
  }

  entries.reserve(count);
  data.reserve(total);

  for (size_t i = 0; i < register_byte_sizes_.size(); ++i) {
    uint16_t size = register_byte_sizes_[i];
    if (size == 0 || register_bytes_known_[i] == 0) {
      continue;
    }

    register_bytes_entry entry{};
    entry.reg_id = static_cast<uint16_t>(i);
    entry.offset = static_cast<uint32_t>(data.size());
    entry.size = size;

    uint32_t offset = register_byte_offsets_[i];
    data.insert(
        data.end(), register_bytes_.begin() + static_cast<std::ptrdiff_t>(offset),
        register_bytes_.begin() + static_cast<std::ptrdiff_t>(offset + size)
    );

    entries.push_back(entry);
  }
}

std::optional<uint64_t> replay_state::register_value(uint16_t reg_id) const {
  if (reg_id >= registers_.size()) {
    return std::nullopt;
  }
  return registers_[reg_id];
}

bool replay_state::copy_register_bytes(uint16_t reg_id, std::span<std::byte> out, bool& known) const {
  if (reg_id >= register_byte_sizes_.size()) {
    return false;
  }
  uint16_t size = register_byte_sizes_[reg_id];
  if (size == 0 || out.size() < size) {
    return false;
  }
  known = register_bytes_known_[reg_id] != 0;
  if (!known) {
    return true;
  }
  uint32_t offset = register_byte_offsets_[reg_id];
  std::memcpy(out.data(), register_bytes_.data() + offset, size);
  return true;
}

void replay_state::apply_memory_bytes(uint64_t address, const std::vector<uint8_t>& data) {
  for (size_t i = 0; i < data.size(); ++i) {
    memory_[address + i] = data[i];
  }
}

void replay_state::apply_stack_snapshot(uint64_t sp, const std::vector<uint8_t>& bytes) {
  if (bytes.empty()) {
    return;
  }
  auto layout = compute_stack_snapshot_layout(sp, static_cast<uint64_t>(bytes.size()));
  if (layout.size == 0) {
    return;
  }
  apply_memory_bytes(layout.base, bytes);
}

std::vector<std::optional<uint8_t>> replay_state::read_memory(uint64_t address, size_t size) const {
  std::vector<std::optional<uint8_t>> out;
  out.reserve(size);
  for (size_t i = 0; i < size; ++i) {
    auto it = memory_.find(address + i);
    if (it == memory_.end()) {
      out.push_back(std::nullopt);
    } else {
      out.push_back(it->second);
    }
  }
  return out;
}

void replay_state::reset_register_bytes() {
  register_byte_offsets_.clear();
  register_byte_sizes_.clear();
  register_bytes_.clear();
  register_bytes_known_.clear();
}

} // namespace w1::rewind
