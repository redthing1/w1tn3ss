#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "code_source.hpp"
#include "module_image.hpp"

#if defined(WITNESS_LIEF_ENABLED)
#include <LIEF/LIEF.hpp>
#include <unordered_map>
#endif

namespace w1replay {

using module_address_reader = std::function<bool(uint64_t address, std::span<std::byte> out, std::string& error)>;

struct macho_header_info {
  uint32_t magic = 0;
  uint32_t cputype = 0;
  uint32_t cpusubtype = 0;
  uint32_t filetype = 0;
};

struct macho_segment_info {
  std::string name;
  uint64_t vmaddr = 0;
  uint64_t vmsize = 0;
  uint64_t fileoff = 0;
  uint64_t filesize = 0;
  uint32_t maxprot = 0;
};

struct module_source : public code_source {
  void configure(std::vector<std::string> module_mappings, std::vector<std::string> module_dirs);
  void set_address_reader(module_address_reader reader);

  void apply_to_context(w1::rewind::replay_context& context);

  image_read_result read_module_image(const w1::rewind::module_record& module, uint64_t module_offset, size_t size);
  image_read_result read_address_image(const w1::rewind::replay_context& context, uint64_t address, size_t size);
  const image_layout* get_module_layout(const w1::rewind::module_record& module, std::string& error);
  std::optional<std::string> get_module_uuid(const w1::rewind::module_record& module, std::string& error);
  std::optional<uint64_t> get_macho_section_va(
      const w1::rewind::module_record& module, std::string_view section_name, std::string& error
  );
  std::optional<macho_header_info> get_macho_header_info(
      const w1::rewind::module_record& module, std::string& error
  );
  std::vector<macho_segment_info> get_macho_segments(
      const w1::rewind::module_record& module, std::string& error
  );

  bool read_by_address(
      const w1::rewind::replay_context& context, uint64_t address, std::span<std::byte> out, std::string& error
  ) override;

private:
  std::vector<std::string> module_mappings_;
  std::vector<std::string> module_dirs_;
  module_address_reader address_reader_{};
  const w1::rewind::replay_context* memory_map_context_ = nullptr;

  struct memory_map_entry {
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t module_base = 0;
    std::string name;
  };

  void ensure_memory_map_index(const w1::rewind::replay_context& context);
  const memory_map_entry* find_memory_map_entry(uint64_t address) const;

  std::vector<memory_map_entry> memory_map_entries_;

#if defined(WITNESS_LIEF_ENABLED)
  struct module_entry {
    std::unique_ptr<LIEF::Binary> binary;
    image_layout layout;
  };

  std::unordered_map<std::string, module_entry> modules_{};

  module_entry* get_or_load_entry(const w1::rewind::module_record& module, std::string& error);
#endif
};

} // namespace w1replay
