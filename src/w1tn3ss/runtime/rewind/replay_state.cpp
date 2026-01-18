#include "replay_state.hpp"

#include <algorithm>

namespace w1::rewind {

void replay_state::reset() {
  registers_.clear();
  memory_.clear();
}

void replay_state::set_register_count(size_t count) {
  registers_.assign(count, std::nullopt);
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

std::optional<uint64_t> replay_state::register_value(uint16_t reg_id) const {
  if (reg_id >= registers_.size()) {
    return std::nullopt;
  }
  return registers_[reg_id];
}

void replay_state::apply_memory_bytes(uint64_t address, const std::vector<uint8_t>& data) {
  for (size_t i = 0; i < data.size(); ++i) {
    memory_[address + i] = data[i];
  }
}

void replay_state::apply_stack_window(uint64_t sp, const std::vector<uint8_t>& bytes) {
  if (bytes.empty()) {
    return;
  }
  auto layout = compute_stack_window_layout(sp, static_cast<uint64_t>(bytes.size()));
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

} // namespace w1::rewind
