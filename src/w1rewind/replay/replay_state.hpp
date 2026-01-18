#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

class replay_state {
public:
  void reset();
  void set_register_count(size_t count);
  void apply_register_snapshot(const std::vector<register_delta>& regs);
  void apply_register_deltas(const std::vector<register_delta>& regs);
  std::optional<uint64_t> register_value(uint16_t reg_id) const;
  const std::vector<std::optional<uint64_t>>& registers() const { return registers_; }
  const std::unordered_map<uint64_t, uint8_t>& memory_map() const { return memory_; }
  void set_memory_map(std::unordered_map<uint64_t, uint8_t> memory) { memory_ = std::move(memory); }

  void apply_memory_bytes(uint64_t address, const std::vector<uint8_t>& data);
  void apply_stack_snapshot(uint64_t sp, const std::vector<uint8_t>& bytes);
  std::vector<std::optional<uint8_t>> read_memory(uint64_t address, size_t size) const;

private:
  void ensure_register_capacity(size_t count);

  std::vector<std::optional<uint64_t>> registers_;
  std::unordered_map<uint64_t, uint8_t> memory_;
};

} // namespace w1::rewind
