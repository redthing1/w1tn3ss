#include "doctest/doctest.hpp"

#include "w1rewind/replay/replay_position.hpp"

namespace {

class test_decoder final : public w1::rewind::block_decoder {
public:
  bool decode_block(
      const w1::rewind::replay_context&, const w1::rewind::flow_step& flow, w1::rewind::decoded_block& out,
      std::string& error
  ) override {
    if (flow.size == 0) {
      error = "block size is zero";
      return false;
    }
    out.start = flow.address;
    out.size = flow.size;
    out.instructions.clear();

    w1::rewind::decoded_instruction first{};
    first.address = flow.address;
    first.size = 2;
    w1::rewind::decoded_instruction second{};
    second.address = flow.address + 2;
    second.size = 2;
    out.instructions.push_back(first);
    out.instructions.push_back(second);
    return true;
  }
};

class failing_decoder final : public w1::rewind::block_decoder {
public:
  bool decode_block(
      const w1::rewind::replay_context&, const w1::rewind::flow_step&, w1::rewind::decoded_block&, std::string& error
  ) override {
    error = "decode failed";
    return false;
  }
};

} // namespace

TEST_CASE("w1rewind replay_position normalizes instruction flow without decoder") {
  w1::rewind::replay_context context;
  w1::rewind::replay_position pos{};
  pos.flow.thread_id = 1;
  pos.flow.sequence = 2;
  pos.flow.address = 0x1000;
  pos.flow.size = 4;
  pos.flow.is_block = false;
  pos.kind = w1::rewind::position_kind::block;

  w1::rewind::position_normalizer normalizer(nullptr);
  std::string error;
  REQUIRE(normalizer.normalize(context, pos, true, error));
  CHECK(pos.kind == w1::rewind::position_kind::instruction);
  REQUIRE(pos.instruction.has_value());
  CHECK(pos.instruction->address == 0x1000);
  CHECK_FALSE(pos.instruction->is_block);
}

TEST_CASE("w1rewind replay_position normalizes block with forward/backward bias") {
  w1::rewind::replay_context context;
  test_decoder decoder;
  w1::rewind::position_normalizer normalizer(&decoder);

  w1::rewind::replay_position pos{};
  pos.flow.address = 0x2000;
  pos.flow.size = 4;
  pos.flow.is_block = true;
  pos.kind = w1::rewind::position_kind::block;

  std::string error;
  REQUIRE(normalizer.normalize(context, pos, true, error));
  CHECK(pos.kind == w1::rewind::position_kind::instruction);
  REQUIRE(pos.instruction.has_value());
  CHECK(pos.instruction->address == 0x2000);

  pos.kind = w1::rewind::position_kind::block;
  pos.instruction.reset();
  REQUIRE(normalizer.normalize(context, pos, false, error));
  REQUIRE(pos.instruction.has_value());
  CHECK(pos.instruction->address == 0x2002);
}

TEST_CASE("w1rewind replay_position reports decode failure") {
  w1::rewind::replay_context context;
  failing_decoder decoder;
  w1::rewind::position_normalizer normalizer(&decoder);

  w1::rewind::replay_position pos{};
  pos.flow.address = 0x3000;
  pos.flow.size = 4;
  pos.flow.is_block = true;
  pos.kind = w1::rewind::position_kind::block;

  std::string error;
  CHECK_FALSE(normalizer.normalize(context, pos, true, error));
  CHECK(error == "decode failed");
  CHECK(pos.kind == w1::rewind::position_kind::block);
  CHECK_FALSE(pos.instruction.has_value());
}
