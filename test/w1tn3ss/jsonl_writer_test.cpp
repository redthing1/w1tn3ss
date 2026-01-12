#include "doctest/doctest.hpp"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

#include "w1tn3ss/io/jsonl_writer.hpp"

namespace {

std::filesystem::path make_temp_path() {
#if defined(_WIN32)
  int pid = _getpid();
#else
  int pid = getpid();
#endif

  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::string name =
      "w1tn3ss_jsonl_writer_" + std::to_string(pid) + "_" + std::to_string(static_cast<long long>(now)) + ".jsonl";
  return std::filesystem::temp_directory_path() / name;
}

std::string read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::in | std::ios::binary);
  std::string contents;
  std::string line;
  while (std::getline(input, line)) {
    contents += line;
    contents += '\n';
  }
  return contents;
}

} // namespace

TEST_CASE("jsonl_writer writes lines with newlines") {
  auto path = make_temp_path();
  w1::io::jsonl_writer_config config;
  config.buffer_size_bytes = 32;
  config.flush_event_count = 0;

  w1::io::jsonl_writer writer(path.string(), config);
  REQUIRE(writer.is_open());

  CHECK(writer.write_line("{\"a\":1}"));
  CHECK(writer.write_line("{\"b\":2}\n"));
  writer.flush();
  writer.close();

  std::string contents = read_file(path);
  CHECK(contents == "{\"a\":1}\n{\"b\":2}\n");

  std::filesystem::remove(path);
}

TEST_CASE("jsonl_writer counts events for raw writes") {
  auto path = make_temp_path();
  w1::io::jsonl_writer_config config;
  config.buffer_size_bytes = 64;
  config.flush_event_count = 0;

  w1::io::jsonl_writer writer(path.string(), config);
  REQUIRE(writer.is_open());

  const char* data = "alpha\nbeta\n";
  CHECK(writer.write_raw(data, std::strlen(data)));
  CHECK(writer.event_count() == 2);
  writer.flush();
  writer.close();

  std::filesystem::remove(path);
}

TEST_CASE("jsonl_writer flushes on byte threshold") {
  auto path = make_temp_path();
  w1::io::jsonl_writer_config config;
  config.buffer_size_bytes = 8;
  config.flush_event_count = 0;
  config.flush_byte_count = 4;

  w1::io::jsonl_writer writer(path.string(), config);
  REQUIRE(writer.is_open());

  const char* data = "abcd";
  CHECK(writer.write_raw(data, 4));
  CHECK(writer.flush_count() == 1);
  writer.close();

  std::filesystem::remove(path);
}
