#include "doctest/doctest.hpp"

#include "w1replay/gdb/lldb/darwin_loaded_libraries.hpp"
#include "w1replay/gdb/loaded_libraries_provider.hpp"
#include "w1replay/modules/metadata_provider.hpp"
#include "w1replay/modules/path_resolver.hpp"
#include "w1rewind/replay/replay_context.hpp"

namespace w1replay::gdb {

namespace {

struct stub_metadata_provider final : public image_metadata_provider {
  std::optional<std::string> image_uuid(const w1::rewind::image_record&, std::string&) override {
    return std::nullopt;
  }
  std::optional<macho_header_info> macho_header(const w1::rewind::image_record&, std::string&) override {
    return std::nullopt;
  }
  std::vector<macho_segment_info> macho_segments(const w1::rewind::image_record&, std::string&) override { return {}; }
};

struct stub_path_resolver final : public image_path_resolver {
  std::optional<std::string> resolve_image_path(const w1::rewind::image_record&) const override {
    return std::nullopt;
  }
  std::optional<std::string> resolve_region_name(std::string_view) const override { return std::nullopt; }
};

} // namespace

TEST_CASE("darwin loaded libraries json includes load commands when requested") {
  gdbstub::lldb::loaded_libraries_request request{};
  request.report_load_commands = true;

  darwin_loaded_image image{};
  image.load_address = 0x1000;
  image.pathname = "/tmp/example";
  image.uuid = "TEST-UUID";
  image.header = macho_header_info{1u, 2u, 3u, 4u};
  image.segments.push_back(macho_segment_info{"__TEXT", 0x1000, 0x2000, 0, 0x2000, 7});

  std::vector<darwin_loaded_image> images{image};
  auto json = build_darwin_loaded_libraries_json(images, request);

  CHECK(json.find("\"load_address\":4096") != std::string::npos);
  CHECK(json.find("\"pathname\"") != std::string::npos);
  CHECK(json.find("\"uuid\"") != std::string::npos);
  CHECK(json.find("\"mach_header\"") != std::string::npos);
  CHECK(json.find("\"segments\"") != std::string::npos);
}

TEST_CASE("darwin loaded libraries json omits load commands when disabled") {
  gdbstub::lldb::loaded_libraries_request request{};
  request.report_load_commands = false;

  darwin_loaded_image image{};
  image.load_address = 0x2000;
  image.pathname = "/tmp/example";
  image.uuid = "TEST-UUID";
  image.header = macho_header_info{1u, 2u, 3u, 4u};
  image.segments.push_back(macho_segment_info{"__TEXT", 0x1000, 0x2000, 0, 0x2000, 7});

  std::vector<darwin_loaded_image> images{image};
  auto json = build_darwin_loaded_libraries_json(images, request);

  CHECK(json.find("\"mach_header\"") == std::string::npos);
  CHECK(json.find("\"segments\"") == std::string::npos);
}

TEST_CASE("loaded libraries provider selection respects target os") {
  w1::rewind::replay_context context{};
  stub_metadata_provider metadata_provider;
  stub_path_resolver resolver;

  context.environment = w1::rewind::environment_record{};
  context.environment->os_id = "macos";
  auto darwin_provider = make_loaded_libraries_provider(context, nullptr, metadata_provider, resolver);
  CHECK(darwin_provider != nullptr);

  context.environment->os_id = "linux";
  auto linux_provider = make_loaded_libraries_provider(context, nullptr, metadata_provider, resolver);
  CHECK(linux_provider == nullptr);
}

} // namespace w1replay::gdb
