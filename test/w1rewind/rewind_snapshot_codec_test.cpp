#include <cstdint>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1rewind/format/trace_codec.hpp"

TEST_CASE("snapshot codec round trip with memory segments") {
  w1::rewind::snapshot_record input{};
  input.sequence = 7;
  input.thread_id = 1;
  input.regfile_id = 0;
  input.registers = {
      w1::rewind::reg_write_entry{w1::rewind::reg_ref_kind::reg_id, 0, 0, 8, 0, "", {0x11, 0x11, 0x00, 0x00,
                                                                                       0x00, 0x00, 0x00, 0x00}},
      w1::rewind::reg_write_entry{w1::rewind::reg_ref_kind::reg_id, 0, 0, 8, 1, "", {0x22, 0x22, 0x00, 0x00,
                                                                                       0x00, 0x00, 0x00, 0x00}},
  };

  w1::rewind::memory_segment seg0{};
  seg0.space_id = 0;
  seg0.base = 0x2000;
  seg0.bytes = {0xAA, 0xBB, 0xCC, 0xDD};
  input.memory_segments.push_back(seg0);

  w1::rewind::memory_segment seg1{};
  seg1.space_id = 0;
  seg1.base = 0x3000;
  seg1.bytes = {0x11, 0x22};
  input.memory_segments.push_back(seg1);

  std::vector<uint8_t> buffer;
  w1::rewind::trace_buffer_writer writer(buffer);
  auto log = redlog::get_logger("test.snapshot_codec");

  REQUIRE(w1::rewind::encode_snapshot(input, writer, log));

  w1::rewind::snapshot_record output{};
  w1::rewind::trace_buffer_reader reader(buffer);
  REQUIRE(w1::rewind::decode_snapshot(reader, output));
  CHECK(reader.remaining() == 0);

  CHECK(output.sequence == input.sequence);
  CHECK(output.thread_id == input.thread_id);
  CHECK(output.regfile_id == input.regfile_id);
  CHECK(output.registers.size() == input.registers.size());
  CHECK(output.memory_segments.size() == input.memory_segments.size());

  for (size_t i = 0; i < input.registers.size(); ++i) {
    CHECK(output.registers[i].reg_id == input.registers[i].reg_id);
    CHECK(output.registers[i].value == input.registers[i].value);
  }

  for (size_t i = 0; i < input.memory_segments.size(); ++i) {
    CHECK(output.memory_segments[i].base == input.memory_segments[i].base);
    CHECK(output.memory_segments[i].space_id == input.memory_segments[i].space_id);
    CHECK(output.memory_segments[i].bytes == input.memory_segments[i].bytes);
  }
}

TEST_CASE("snapshot codec rejects truncated payload") {
  w1::rewind::snapshot_record input{};
  input.sequence = 1;
  input.thread_id = 1;
  input.regfile_id = 0;

  w1::rewind::memory_segment seg{};
  seg.space_id = 0;
  seg.base = 0x4000;
  seg.bytes = {0x00, 0x01, 0x02};
  input.memory_segments.push_back(seg);

  std::vector<uint8_t> buffer;
  w1::rewind::trace_buffer_writer writer(buffer);
  auto log = redlog::get_logger("test.snapshot_codec");

  REQUIRE(w1::rewind::encode_snapshot(input, writer, log));

  buffer.pop_back();
  w1::rewind::snapshot_record output{};
  w1::rewind::trace_buffer_reader reader(buffer);
  CHECK_FALSE(w1::rewind::decode_snapshot(reader, output));
}
