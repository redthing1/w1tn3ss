#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "gdbstub/lldb/types.hpp"

#include "w1replay/gdb/loaded_libraries_provider.hpp"
#include "w1replay/modules/metadata_provider.hpp"
#include "w1replay/modules/path_resolver.hpp"

namespace w1replay::gdb {

struct darwin_loaded_image {
  uint64_t load_address = 0;
  std::string pathname;
  std::optional<std::string> uuid;
  std::optional<macho_header_info> header;
  std::vector<macho_segment_info> segments;
};

std::string build_darwin_loaded_libraries_json(
    const std::vector<darwin_loaded_image>& images, const gdbstub::lldb::loaded_libraries_request& request
);

class darwin_loaded_libraries_provider final : public loaded_libraries_provider {
public:
  darwin_loaded_libraries_provider(
      const w1::rewind::replay_context& context, const w1::rewind::mapping_state* mappings,
      image_metadata_provider& metadata_provider, image_path_resolver& resolver
  );

  std::optional<std::string> loaded_libraries_json(const gdbstub::lldb::loaded_libraries_request& request) override;
  std::optional<std::vector<gdbstub::lldb::process_kv_pair>> process_info_extras(
      std::optional<uint64_t> current_pc
  ) const override;
  bool has_loaded_images() const override;

private:
  std::vector<darwin_loaded_image> collect_loaded_images(const gdbstub::lldb::loaded_libraries_request& request) const;

  const w1::rewind::replay_context& context_;
  const w1::rewind::mapping_state* mappings_ = nullptr;
  image_metadata_provider& metadata_provider_;
  image_path_resolver& resolver_;
};

} // namespace w1replay::gdb
