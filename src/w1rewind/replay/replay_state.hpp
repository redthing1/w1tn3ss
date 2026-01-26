#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/replay/memory_store.hpp"

namespace w1::rewind {

class replay_state {
public:
  void reset();
  void set_register_files(const std::vector<register_file_record>& files);
  bool apply_reg_write(uint32_t regfile_id, const std::vector<reg_write_entry>& entries, std::string& error);
  bool apply_register_snapshot(uint32_t regfile_id, const std::vector<reg_write_entry>& entries, std::string& error);
  std::optional<uint64_t> register_value(uint32_t regfile_id, uint32_t reg_id, endian byte_order) const;
  bool copy_register_bytes(uint32_t regfile_id, uint32_t reg_id, std::span<std::byte> out, bool& known) const;
  std::vector<reg_write_entry> collect_register_writes(uint32_t regfile_id) const;

  const memory_store& memory_store() const { return memory_; }
  void set_memory_segments(std::span<const memory_segment> segments);

  void apply_memory_bytes(uint32_t space_id, uint64_t address, std::span<const uint8_t> data);
  void apply_memory_segments(const std::vector<memory_segment>& segments);
  memory_read read_memory(uint32_t space_id, uint64_t address, size_t size) const;

private:
  struct register_slot {
    uint32_t reg_id = 0;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> known;
  };

  struct register_bank {
    std::unordered_map<uint32_t, size_t> id_to_index;
    std::unordered_map<std::string, uint32_t> name_to_id;
    std::vector<register_slot> register_slots;
  };

  register_bank* find_bank(uint32_t regfile_id);
  const register_bank* find_bank(uint32_t regfile_id) const;
  void reset_register_bank(register_bank& bank);
  static register_slot* ensure_slot(register_bank& bank, uint32_t reg_id, uint32_t min_size);

  std::unordered_map<uint32_t, register_bank> banks_;
  w1::rewind::memory_store memory_;
};

} // namespace w1::rewind
