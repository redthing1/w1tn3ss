#pragma once

#include <cstdint>

namespace gdbstub {
struct arch_spec;
}

#include "breakpoint_store.hpp"
#include "run_policy.hpp"
#include "value_codec.hpp"
#include "w1rewind/replay/replay_session.hpp"
#include "w1replay/memory/memory_view.hpp"
#include "w1replay/modules/address_index.hpp"
#include "w1replay/modules/image_reader.hpp"
#include "w1replay/modules/metadata_provider.hpp"
#include "w1replay/modules/path_resolver.hpp"
#include "loaded_libraries_provider.hpp"
#include "layout.hpp"

namespace w1replay::gdb {

struct adapter_services {
  w1::rewind::replay_session* session = nullptr;
  const w1::rewind::replay_context* context = nullptr;
  const register_layout* layout = nullptr;
  const gdbstub::arch_spec* arch_spec = nullptr;
  module_path_resolver* module_resolver = nullptr;
  module_image_reader* module_reader = nullptr;
  module_metadata_provider* module_metadata = nullptr;
  module_address_index* module_index = nullptr;
  memory_view* memory = nullptr;
  loaded_libraries_provider* loaded_libraries = nullptr;
  breakpoint_store* breakpoints = nullptr;
  run_policy run_policy{};
  endian target_endian = endian::little;
  bool track_memory = false;
};

} // namespace w1replay::gdb
