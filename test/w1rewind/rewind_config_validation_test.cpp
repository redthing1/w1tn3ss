#include <string>

#include "doctest/doctest.hpp"

#include "tracers/w1rewind/config/rewind_config.hpp"

TEST_CASE("rewind config rejects invalid combinations") {
  std::string error;
  w1rewind::rewind_config config;

  config.registers.bytes = true;
  CHECK(!config.validate(error));
  CHECK(error.find("register byte capture") != std::string::npos);

  config = w1rewind::rewind_config{};
  config.flow.mode = w1rewind::rewind_config::flow_options::flow_mode::block;
  config.registers.deltas = true;
  CHECK(!config.validate(error));
  CHECK(error.find("flow=block") != std::string::npos);

  config = w1rewind::rewind_config{};
  config.stack_snapshots.interval = 1;
  config.stack_window.mode = w1rewind::rewind_config::stack_window_options::window_mode::none;
  CHECK(!config.validate(error));
  CHECK(error.find("stack snapshots") != std::string::npos);

  config = w1rewind::rewind_config{};
  config.memory.values = true;
  config.memory.access = w1rewind::rewind_config::memory_access::none;
  CHECK(!config.validate(error));
  CHECK(error.find("memory values") != std::string::npos);

  config = w1rewind::rewind_config{};
  config.memory.filters = {w1rewind::rewind_config::memory_filter_kind::ranges};
  config.memory.ranges.clear();
  CHECK(!config.validate(error));
  CHECK(error.find("MEM_RANGES") != std::string::npos);

  config = w1rewind::rewind_config{};
  config.memory.filters = {w1rewind::rewind_config::memory_filter_kind::stack_window};
  config.stack_window.mode = w1rewind::rewind_config::stack_window_options::window_mode::none;
  CHECK(!config.validate(error));
  CHECK(error.find("stack window") != std::string::npos);
}

TEST_CASE("rewind config accepts valid combinations") {
  std::string error;
  w1rewind::rewind_config config;
  config.flow.mode = w1rewind::rewind_config::flow_options::flow_mode::instruction;
  config.registers.deltas = true;
  config.registers.snapshot_interval = 4;
  config.stack_window.mode = w1rewind::rewind_config::stack_window_options::window_mode::fixed;
  config.stack_window.above_bytes = 16;
  config.stack_window.below_bytes = 32;
  config.stack_window.max_total_bytes = 64;
  config.stack_snapshots.interval = 1;
  config.memory.access = w1rewind::rewind_config::memory_access::reads_writes;
  config.memory.values = true;
  config.memory.filters = {w1rewind::rewind_config::memory_filter_kind::stack_window};

  CHECK(config.validate(error));
  CHECK(error.empty());
}
