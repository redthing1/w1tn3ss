#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "address_index.hpp"
#include "image_reader.hpp"
#include "metadata_provider.hpp"
#include "path_resolver.hpp"

#if defined(WITNESS_LIEF_ENABLED)
#include <LIEF/LIEF.hpp>
#endif

namespace w1replay {

struct lief_module_provider_config {
  const module_path_resolver* resolver = nullptr;
  const module_address_index* address_index = nullptr;
  module_address_reader address_reader{};
};

class lief_module_provider final : public module_image_reader, public module_metadata_provider {
public:
  explicit lief_module_provider(lief_module_provider_config config);

  image_read_result read_module_bytes(
      const w1::rewind::module_record& module, uint64_t offset, size_t size
  ) override;
  image_read_result read_address_bytes(
      const w1::rewind::replay_context& context, uint64_t address, size_t size
  ) override;
  const image_layout* module_layout(const w1::rewind::module_record& module, std::string& error) override;

  std::optional<std::string> module_uuid(
      const w1::rewind::module_record& module, std::string& error
  ) override;
  std::optional<macho_header_info> macho_header(
      const w1::rewind::module_record& module, std::string& error
  ) override;
  std::vector<macho_segment_info> macho_segments(
      const w1::rewind::module_record& module, std::string& error
  ) override;

private:
  std::string resolved_module_path(const w1::rewind::module_record& module) const;

  const module_path_resolver* resolver_ = nullptr;
  const module_address_index* address_index_ = nullptr;
  module_address_reader address_reader_{};

#if defined(WITNESS_LIEF_ENABLED)
  struct module_entry {
    std::unique_ptr<LIEF::Binary> binary;
    image_layout layout;
  };

  std::unordered_map<std::string, module_entry> modules_;

  module_entry* get_or_load_entry(const w1::rewind::module_record& module, std::string& error);
#endif
};

} // namespace w1replay
