#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "module_image.hpp"
#include "w1rewind/replay/replay_context.hpp"

#if defined(WITNESS_LIEF_ENABLED)
#include <LIEF/LIEF.hpp>
#include <unordered_map>
#endif

namespace w1replay {

using module_address_reader = std::function<bool(uint64_t address, std::span<std::byte> out, std::string& error)>;

struct module_source {
  void configure(std::vector<std::string> module_mappings, std::vector<std::string> module_dirs);
  void set_address_reader(module_address_reader reader);

  void apply_to_context(w1::rewind::replay_context& context);

  image_read_result read_module_image(const w1::rewind::module_record& module, uint64_t module_offset, size_t size);
  image_read_result read_address_image(const w1::rewind::replay_context& context, uint64_t address, size_t size);
  const image_layout* get_module_layout(const w1::rewind::module_record& module, std::string& error);

private:
  std::vector<std::string> module_mappings_;
  std::vector<std::string> module_dirs_;
  module_address_reader address_reader_{};

#if defined(WITNESS_LIEF_ENABLED)
  struct module_entry {
    std::unique_ptr<LIEF::Binary> binary;
    image_layout layout;
  };

  std::unordered_map<std::string, module_entry> modules_{};
#endif
};

} // namespace w1replay
