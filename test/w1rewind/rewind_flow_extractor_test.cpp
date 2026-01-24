#include "doctest/doctest.hpp"

#include "w1rewind/replay/flow_extractor.hpp"

namespace {

struct test_observer final : public w1::rewind::flow_record_observer {
  size_t seen = 0;
  bool on_record(const w1::rewind::trace_record&, uint64_t, std::string&) override {
    ++seen;
    return true;
  }
};

} // namespace

TEST_CASE("w1rewind flow_extractor parses instruction records") {
  w1::rewind::replay_context context;
  w1::rewind::flow_extractor extractor(&context);

  w1::rewind::instruction_record inst{};
  inst.thread_id = 7;
  inst.sequence = 9;
  inst.address = 0x401000;
  inst.size = 4;
  inst.flags = 0x12;

  w1::rewind::trace_record record = inst;
  w1::rewind::flow_step step{};
  bool is_flow = false;
  std::string error;

  REQUIRE(extractor.try_extract(record, step, is_flow, error));
  CHECK(is_flow);
  CHECK(step.thread_id == 7);
  CHECK(step.sequence == 9);
  CHECK(step.address == 0x401000);
  CHECK(step.size == 4);
  CHECK(step.flags == 0x12);
  CHECK_FALSE(step.is_block);
}

TEST_CASE("w1rewind flow_extractor skips non-flow records") {
  w1::rewind::replay_context context;
  w1::rewind::flow_extractor extractor(&context);

  w1::rewind::module_table_record table{};
  w1::rewind::trace_record record = table;
  w1::rewind::flow_step step{};
  bool is_flow = true;
  std::string error;

  REQUIRE(extractor.try_extract(record, step, is_flow, error));
  CHECK_FALSE(is_flow);
}

TEST_CASE("w1rewind flow_extractor parses block records") {
  w1::rewind::replay_context context;
  w1::rewind::block_definition_record def{};
  def.address = 0x5000;
  def.size = 8;
  def.flags = 0;
  context.blocks_by_id[42] = def;

  w1::rewind::flow_extractor extractor(&context);
  extractor.set_flow_kind(w1::rewind::flow_kind::blocks);

  w1::rewind::block_exec_record exec{};
  exec.thread_id = 3;
  exec.sequence = 11;
  exec.block_id = 42;

  w1::rewind::trace_record record = exec;
  w1::rewind::flow_step step{};
  bool is_flow = false;
  std::string error;

  REQUIRE(extractor.try_extract(record, step, is_flow, error));
  CHECK(is_flow);
  CHECK(step.thread_id == 3);
  CHECK(step.sequence == 11);
  CHECK(step.address == 0x5000);
  CHECK(step.size == 8);
  CHECK(step.block_id == 42);
  CHECK(step.is_block);
}

TEST_CASE("w1rewind flow_extractor errors on missing block id") {
  w1::rewind::replay_context context;
  w1::rewind::flow_extractor extractor(&context);
  extractor.set_flow_kind(w1::rewind::flow_kind::blocks);

  w1::rewind::block_exec_record exec{};
  exec.thread_id = 1;
  exec.sequence = 0;
  exec.block_id = 99;

  w1::rewind::trace_record record = exec;
  w1::rewind::flow_step step{};
  bool is_flow = false;
  std::string error;

  CHECK_FALSE(extractor.try_extract(record, step, is_flow, error));
  CHECK(error == "block id not found");
}

TEST_CASE("w1rewind flow_extractor forwards non-flow records to observer") {
  w1::rewind::replay_context context;
  w1::rewind::flow_extractor extractor(&context);

  w1::rewind::module_table_record table{};
  w1::rewind::trace_record record = table;
  test_observer observer;
  std::string error;

  REQUIRE(extractor.handle_non_flow(record, &observer, 1, error));
  CHECK(observer.seen == 1);
}
