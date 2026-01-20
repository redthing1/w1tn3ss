#include <cstdint>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1rewind/format/trace_codec.hpp"

TEST_CASE("snapshot codec round trip with stack segments") {
  w1::rewind::snapshot_record input{};
  input.snapshot_id = 42;
  input.sequence = 7;
  input.thread_id = 1;
  input.registers = {
      w1::rewind::register_delta{0, 0x1111},
      w1::rewind::register_delta{1, 0x2222},
  };

  w1::rewind::stack_segment seg0{};
  seg0.base = 0x2000;
  seg0.size = 4;
  seg0.bytes = {0xAA, 0xBB, 0xCC, 0xDD};
  input.stack_segments.push_back(seg0);

  w1::rewind::stack_segment seg1{};
  seg1.base = 0x3000;
  seg1.size = 2;
  seg1.bytes = {0x11, 0x22};
  input.stack_segments.push_back(seg1);

  input.reason = "interval";

  std::vector<uint8_t> buffer;
  w1::rewind::trace_buffer_writer writer(buffer);
  auto log = redlog::get_logger("test.snapshot_codec");

  REQUIRE(w1::rewind::encode_snapshot(input, writer, log));

  w1::rewind::snapshot_record output{};
  w1::rewind::trace_buffer_reader reader(buffer);
  REQUIRE(w1::rewind::decode_snapshot(reader, output));
  CHECK(reader.remaining() == 0);

  CHECK(output.snapshot_id == input.snapshot_id);
  CHECK(output.sequence == input.sequence);
  CHECK(output.thread_id == input.thread_id);
  CHECK(output.registers.size() == input.registers.size());
  CHECK(output.stack_segments.size() == input.stack_segments.size());
  CHECK(output.reason == input.reason);

  for (size_t i = 0; i < input.registers.size(); ++i) {
    CHECK(output.registers[i].reg_id == input.registers[i].reg_id);
    CHECK(output.registers[i].value == input.registers[i].value);
  }

  for (size_t i = 0; i < input.stack_segments.size(); ++i) {
    CHECK(output.stack_segments[i].base == input.stack_segments[i].base);
    CHECK(output.stack_segments[i].size == input.stack_segments[i].size);
    CHECK(output.stack_segments[i].bytes == input.stack_segments[i].bytes);
  }
}

TEST_CASE("snapshot codec rejects size mismatch") {
  w1::rewind::snapshot_record input{};
  input.snapshot_id = 1;
  input.sequence = 1;
  input.thread_id = 1;
  input.reason = "bad";

  w1::rewind::stack_segment seg{};
  seg.base = 0x4000;
  seg.size = 4;
  seg.bytes = {0x00, 0x01};
  input.stack_segments.push_back(seg);

  std::vector<uint8_t> buffer;
  w1::rewind::trace_buffer_writer writer(buffer);
  auto log = redlog::get_logger("test.snapshot_codec");

  CHECK_FALSE(w1::rewind::encode_snapshot(input, writer, log));
}
