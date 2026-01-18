#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "code_source.hpp"

#if defined(WITNESS_LIEF_ENABLED)
#include <LIEF/LIEF.hpp>
#include <unordered_map>
#endif

namespace w1replay {

using module_address_reader = std::function<bool(uint64_t address, std::span<std::byte> out, std::string& error)>;

struct module_source : public code_source {
  void configure(std::vector<std::string> module_mappings, std::vector<std::string> module_dirs);
  void set_address_reader(module_address_reader reader);

  void apply_to_context(w1::rewind::replay_context& context);

  bool read_module_bytes(
      const w1::rewind::module_record& module,
      uint64_t module_offset,
      uint32_t size,
      std::vector<std::byte>& out,
      std::string& error
  );

  bool read_address_bytes(
      const w1::rewind::replay_context& context,
      uint64_t address,
      std::span<std::byte> out,
      std::string& error
  );

  bool read_by_module(
      const w1::rewind::replay_context& context,
      uint64_t module_id,
      uint64_t module_offset,
      uint32_t size,
      std::vector<std::byte>& out,
      std::string& error
  ) override;

  bool read_by_address(
      const w1::rewind::replay_context& context,
      uint64_t address,
      std::span<std::byte> out,
      std::string& error
  ) override;

private:
  std::vector<std::string> module_mappings_;
  std::vector<std::string> module_dirs_;
  module_address_reader address_reader_{};

#if defined(WITNESS_LIEF_ENABLED)
  struct module_entry {
    std::string path;
    std::unique_ptr<LIEF::Binary> binary;
  };

  std::unordered_map<std::string, module_entry> modules_{};
#endif
};

} // namespace w1replay
