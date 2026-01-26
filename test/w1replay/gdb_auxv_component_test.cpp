#include <cstddef>
#include <cstdint>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1replay/gdb/adapter_components.hpp"
#include "w1rewind/replay/replay_context.hpp"

namespace {

uint64_t read_u64_le(const std::vector<std::byte>& data, size_t offset) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(std::to_integer<uint8_t>(data[offset + i])) << (i * 8);
  }
  return value;
}

} // namespace

TEST_CASE("gdb auxv uses image metadata for entrypoint") {
  w1::rewind::replay_context context{};

  w1::rewind::environment_record env{};
  env.os_id = "linux";
  context.environment = env;

  w1::rewind::arch_descriptor_record arch{};
  arch.arch_id = "x86_64";
  arch.pointer_bits = 64;
  arch.address_bits = 64;
  arch.byte_order = w1::rewind::endian::little;
  context.arch = arch;

  w1::rewind::image_record image{};
  image.image_id = 1;
  image.flags = w1::rewind::image_flag_main;
  context.images.push_back(image);
  context.images_by_id[1] = 0;

  w1::rewind::mapping_record mapping{};
  mapping.space_id = 0;
  mapping.base = 0x400000;
  mapping.size = 0x1000;
  mapping.image_id = 1;
  mapping.image_offset = 0;
  context.mappings.push_back(mapping);

  w1::rewind::image_metadata_record meta{};
  meta.image_id = 1;
  meta.flags = w1::rewind::image_meta_has_entry_point | w1::rewind::image_meta_has_link_base;
  meta.entry_point = 0x1100;
  meta.link_base = 0x1000;
  context.image_metadata_by_id[1] = meta;

  w1replay::gdb::adapter_services services{};
  services.context = &context;
  services.target_endian = w1replay::gdb::endian::little;

  w1replay::gdb::auxv_component auxv(services);
  auto data = auxv.auxv_data();
  REQUIRE(data.has_value());
  REQUIRE(data->size() == 32);

  uint64_t type0 = read_u64_le(*data, 0);
  uint64_t value0 = read_u64_le(*data, 8);
  uint64_t type1 = read_u64_le(*data, 16);
  uint64_t value1 = read_u64_le(*data, 24);

  CHECK(type0 == 9);
  CHECK(value0 == 0x400100);
  CHECK(type1 == 0);
  CHECK(value1 == 0);
}
