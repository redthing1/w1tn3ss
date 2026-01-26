#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gdbstub/lldb/types.hpp"

namespace w1::rewind {
struct replay_context;
class mapping_state;
}

namespace w1replay {
class image_metadata_provider;
class image_path_resolver;
} // namespace w1replay

namespace w1replay::gdb {

class loaded_libraries_provider {
public:
  virtual ~loaded_libraries_provider() = default;

  virtual std::optional<std::string> loaded_libraries_json(const gdbstub::lldb::loaded_libraries_request& request) = 0;
  virtual std::optional<std::vector<gdbstub::lldb::process_kv_pair>> process_info_extras(
      std::optional<uint64_t> current_pc
  ) const = 0;
  virtual bool has_loaded_images() const = 0;
};

std::unique_ptr<loaded_libraries_provider> make_loaded_libraries_provider(
    const w1::rewind::replay_context& context, const w1::rewind::mapping_state* mappings,
    image_metadata_provider& metadata_provider, image_path_resolver& resolver
);

} // namespace w1replay::gdb
