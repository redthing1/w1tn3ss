#include "doctest/doctest.hpp"

#include "w1replay/modules/composite_image_provider.hpp"
#include "w1rewind/replay/replay_context.hpp"

TEST_CASE("composite_image_provider uses trace image metadata") {
  w1::rewind::replay_context context{};

  w1::rewind::image_record image{};
  image.image_id = 1;
  image.name = "example";
  context.images.push_back(image);
  context.images_by_id[1] = 0;

  w1::rewind::image_metadata_record meta{};
  meta.image_id = 1;
  meta.format = "macho";
  meta.flags = w1::rewind::image_meta_has_uuid | w1::rewind::image_meta_has_macho_header |
               w1::rewind::image_meta_has_segments;
  meta.uuid = "TRACE-UUID";
  meta.macho_header.magic = 1;
  meta.macho_header.cputype = 2;
  meta.macho_header.cpusubtype = 3;
  meta.macho_header.filetype = 4;
  meta.segments.push_back({"__TEXT", 0x1000, 0x2000, 0, 0x2000, 7});
  context.image_metadata_by_id[1] = meta;

  w1replay::composite_image_provider_config config{};
  config.context = &context;
  w1replay::composite_image_provider provider(config);

  std::string error;
  auto uuid = provider.image_uuid(context.images[0], error);
  REQUIRE(uuid.has_value());
  CHECK(*uuid == "TRACE-UUID");

  auto header = provider.macho_header(context.images[0], error);
  REQUIRE(header.has_value());
  CHECK(header->magic == 1);
  CHECK(header->cputype == 2);
  CHECK(header->cpusubtype == 3);
  CHECK(header->filetype == 4);

  auto segments = provider.macho_segments(context.images[0], error);
  REQUIRE(segments.size() == 1);
  CHECK(segments[0].name == "__TEXT");
  CHECK(segments[0].vmaddr == 0x1000);
  CHECK(segments[0].vmsize == 0x2000);
  CHECK(segments[0].fileoff == 0);
  CHECK(segments[0].filesize == 0x2000);
  CHECK(segments[0].maxprot == 7);
}

TEST_CASE("composite_image_provider returns empty metadata when missing") {
  w1::rewind::replay_context context{};

  w1::rewind::image_record image{};
  image.image_id = 2;
  image.name = "no-metadata";
  context.images.push_back(image);
  context.images_by_id[2] = 0;

  w1replay::composite_image_provider_config config{};
  config.context = &context;
  w1replay::composite_image_provider provider(config);

  std::string error;
  auto uuid = provider.image_uuid(context.images[0], error);
  CHECK(!uuid.has_value());
  CHECK(error.empty());

  auto header = provider.macho_header(context.images[0], error);
  CHECK(!header.has_value());
  CHECK(error.empty());

  auto segments = provider.macho_segments(context.images[0], error);
  CHECK(segments.empty());
  CHECK(error.empty());
}
