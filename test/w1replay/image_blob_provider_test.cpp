#include <cstddef>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1replay/modules/address_index.hpp"
#include "w1replay/modules/composite_image_provider.hpp"
#include "w1rewind/replay/replay_context.hpp"

TEST_CASE("composite_image_provider reads embedded image blobs by image id") {
  w1::rewind::replay_context context;

  w1::rewind::image_record image{};
  image.image_id = 1;
  image.name = "rom.bin";
  context.images.push_back(image);
  context.images_by_id[1] = 0;

  w1::rewind::image_blob_record blob{};
  blob.image_id = 1;
  blob.offset = 4;
  blob.data = {0xAA, 0xBB, 0xCC};
  context.image_blobs_by_id[1].push_back(blob);

  w1replay::composite_image_provider_config config{};
  config.context = &context;
  w1replay::composite_image_provider provider(config);

  auto result = provider.read_image_bytes(context.images[0], 2, 6);
  CHECK(result.error.empty());
  CHECK(result.bytes.size() == 6);
  CHECK(result.known.size() == 6);
  CHECK(result.known[0] == 0);
  CHECK(result.known[1] == 0);
  CHECK(result.known[2] == 1);
  CHECK(result.known[3] == 1);
  CHECK(result.known[4] == 1);
  CHECK(result.bytes[2] == std::byte{0xAA});
  CHECK(result.bytes[3] == std::byte{0xBB});
  CHECK(result.bytes[4] == std::byte{0xCC});
}

TEST_CASE("composite_image_provider reads embedded image blobs by address") {
  w1::rewind::replay_context context;

  w1::rewind::image_record image{};
  image.image_id = 1;
  image.name = "rom.bin";
  context.images.push_back(image);
  context.images_by_id[1] = 0;

  w1::rewind::image_blob_record blob{};
  blob.image_id = 1;
  blob.offset = 2;
  blob.data = {0x10, 0x20, 0x30, 0x40};
  context.image_blobs_by_id[1].push_back(blob);

  w1::rewind::mapping_record mapping{};
  mapping.space_id = 0;
  mapping.base = 0x1000;
  mapping.size = 0x100;
  mapping.image_id = 1;
  mapping.image_offset = 0;
  context.mappings.push_back(mapping);
  context.mapping_ranges_by_space[0] = {
      {mapping.base, mapping.base + mapping.size, &context.mappings[0]},
  };

  w1replay::image_address_index index(context);
  w1replay::composite_image_provider_config config{};
  config.context = &context;
  config.address_index = &index;
  w1replay::composite_image_provider provider(config);

  auto result = provider.read_address_bytes(context, 0x1002, 4, 0);
  CHECK(result.error.empty());
  CHECK(result.bytes.size() == 4);
  CHECK(result.known.size() == 4);
  CHECK(result.known[0] == 1);
  CHECK(result.known[1] == 1);
  CHECK(result.known[2] == 1);
  CHECK(result.known[3] == 1);
  CHECK(result.bytes[0] == std::byte{0x10});
  CHECK(result.bytes[1] == std::byte{0x20});
  CHECK(result.bytes[2] == std::byte{0x30});
  CHECK(result.bytes[3] == std::byte{0x40});
}

TEST_CASE("composite_image_provider does not use recorded paths without resolver") {
  w1::rewind::replay_context context;

  w1::rewind::image_record image{};
  image.image_id = 1;
  image.name = "no-resolver";
  image.path = "/nonexistent/path.bin";
  context.images.push_back(image);
  context.images_by_id[1] = 0;

  w1replay::composite_image_provider_config config{};
  config.context = &context;
  w1replay::composite_image_provider provider(config);

  auto result = provider.read_image_bytes(context.images[0], 0, 4);
  CHECK(result.error == "image bytes unavailable");
  CHECK(!result.complete);
}

TEST_CASE("composite_image_provider respects mapping range boundaries for address reads") {
  w1::rewind::replay_context context;

  w1::rewind::image_record image1{};
  image1.image_id = 1;
  image1.name = "image-one";
  context.images.push_back(image1);
  context.images_by_id[1] = 0;

  w1::rewind::image_record image2{};
  image2.image_id = 2;
  image2.name = "image-two";
  context.images.push_back(image2);
  context.images_by_id[2] = 1;

  w1::rewind::image_blob_record blob1{};
  blob1.image_id = 1;
  blob1.offset = 0;
  blob1.data.assign(0x100, 0x11);
  context.image_blobs_by_id[1].push_back(blob1);

  w1::rewind::image_blob_record blob2{};
  blob2.image_id = 2;
  blob2.offset = 0;
  blob2.data.assign(0x80, 0x22);
  context.image_blobs_by_id[2].push_back(blob2);

  w1::rewind::mapping_record mapping1{};
  mapping1.space_id = 0;
  mapping1.base = 0x1000;
  mapping1.size = 0x100;
  mapping1.image_id = 1;
  mapping1.image_offset = 0;
  context.mappings.push_back(mapping1);

  w1::rewind::mapping_record mapping2{};
  mapping2.space_id = 0;
  mapping2.base = 0x1080;
  mapping2.size = 0x80;
  mapping2.image_id = 2;
  mapping2.image_offset = 0;
  context.mappings.push_back(mapping2);

  context.mapping_ranges_by_space[0] = {
      {0x1000, 0x1080, &context.mappings[0]},
      {0x1080, 0x1100, &context.mappings[1]},
  };

  w1replay::image_address_index index(context);
  w1replay::composite_image_provider_config config{};
  config.context = &context;
  config.address_index = &index;
  w1replay::composite_image_provider provider(config);

  auto result = provider.read_address_bytes(context, 0x1070, 0x40, 0);
  CHECK(result.error.empty());
  REQUIRE(result.bytes.size() == 0x40);
  REQUIRE(result.known.size() == 0x40);
  CHECK(result.known[0] == 1);
  CHECK(result.known[0x0F] == 1);
  CHECK(result.known[0x10] == 1);
  CHECK(result.known[0x3F] == 1);
  CHECK(result.bytes[0] == std::byte{0x11});
  CHECK(result.bytes[0x0F] == std::byte{0x11});
  CHECK(result.bytes[0x10] == std::byte{0x22});
  CHECK(result.bytes[0x3F] == std::byte{0x22});
}
