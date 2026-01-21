#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/replay/memory_store.hpp"

namespace w1::rewind {

class replay_state {
public:
  void reset();
  void set_register_specs(const std::vector<register_spec>& specs);
  void set_register_count(size_t count);
  void apply_register_snapshot(const std::vector<register_delta>& regs);
  void apply_register_deltas(const std::vector<register_delta>& regs);
  bool apply_register_bytes(const std::vector<register_bytes_entry>& entries, const std::vector<uint8_t>& data);
  void collect_register_bytes(std::vector<register_bytes_entry>& entries, std::vector<uint8_t>& data) const;
  std::optional<uint64_t> register_value(uint16_t reg_id) const;
  bool copy_register_bytes(uint16_t reg_id, std::span<std::byte> out, bool& known) const;
  const std::vector<std::optional<uint64_t>>& registers() const { return registers_; }
  const memory_store& memory_store() const { return memory_; }
  void set_memory_spans(std::span<const memory_span> spans);

  void apply_memory_bytes(uint64_t address, std::span<const uint8_t> data);
  void apply_stack_segments(const std::vector<stack_segment>& segments);
  memory_read read_memory(uint64_t address, size_t size) const;

private:
  void ensure_register_capacity(size_t count);
  void reset_register_bytes();

  std::vector<std::optional<uint64_t>> registers_;
  std::vector<uint32_t> register_byte_offsets_;
  std::vector<uint16_t> register_byte_sizes_;
  std::vector<uint8_t> register_bytes_;
  std::vector<uint8_t> register_bytes_known_;
  w1::rewind::memory_store memory_;
};

} // namespace w1::rewind
