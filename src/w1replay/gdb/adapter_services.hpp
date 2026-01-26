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
  const w1::rewind::mapping_state* mappings = nullptr;
  const register_layout* layout = nullptr;
  const gdbstub::arch_spec* arch_spec = nullptr;
  image_path_resolver* image_resolver = nullptr;
  image_reader* image_reader = nullptr;
  image_metadata_provider* image_metadata = nullptr;
  image_address_index* image_index = nullptr;
  memory_view* memory = nullptr;
  loaded_libraries_provider* loaded_libraries = nullptr;
  breakpoint_store* breakpoints = nullptr;
  run_policy run_policy{};
  endian target_endian = endian::little;
  bool track_memory = false;
};

} // namespace w1replay::gdb
