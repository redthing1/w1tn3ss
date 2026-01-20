#include "doctest/doctest.hpp"

#include "w1replay/gdb/lldb/darwin_loaded_libraries.hpp"
#include "w1replay/gdb/loaded_libraries_provider.hpp"
#include "w1replay/module_source.hpp"
#include "w1rewind/replay/replay_context.hpp"

namespace w1replay::gdb {

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
  context.target_info = w1::rewind::target_info_record{};
  w1replay::module_source module_source;

  context.target_info->os = "macos";
  auto darwin_provider = make_loaded_libraries_provider(context, module_source);
  CHECK(darwin_provider != nullptr);

  context.target_info->os = "linux";
  auto linux_provider = make_loaded_libraries_provider(context, module_source);
  CHECK(linux_provider == nullptr);
}

} // namespace w1replay::gdb
