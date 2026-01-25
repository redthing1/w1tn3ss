#include <vector>

#include "doctest/doctest.hpp"

#include "tracers/w1rewind/thread/memory_filter.hpp"
#include "tracers/w1rewind/thread/stack_window_policy.hpp"

TEST_CASE("memory filter matches all selectors") {
  w1rewind::rewind_config::memory_options options{};
  options.filters.clear();
  w1rewind::memory_filter filter(options);

  auto out = filter.filter(0x1000, 0x20, {});
  REQUIRE(out.size() == 1);
  CHECK(out[0].start == 0x1000);
  CHECK(out[0].end == 0x1020);
}

TEST_CASE("memory filter intersects explicit ranges") {
  w1rewind::rewind_config::memory_options options{};
  options.filters = {w1rewind::rewind_config::memory_filter_kind::ranges};
  options.ranges = {
      {0x1000, 0x1100},
      {0x1200, 0x1300},
  };
  w1rewind::memory_filter filter(options);

  auto out = filter.filter(0x1050, 0x200, {});
  REQUIRE(out.size() == 2);
  CHECK(out[0].start == 0x1050);
  CHECK(out[0].end == 0x1100);
  CHECK(out[1].start == 0x1200);
  CHECK(out[1].end == 0x1250);
}

TEST_CASE("memory filter intersects stack window segments") {
  w1rewind::rewind_config::memory_options options{};
  options.filters = {w1rewind::rewind_config::memory_filter_kind::stack_window};
  w1rewind::memory_filter filter(options);

  std::vector<w1rewind::stack_window_segment> segments = {
      {0x2000, 0x40},
      {0x2100, 0x20},
  };

  auto out = filter.filter(0x1FF0, 0x40, segments);
  REQUIRE(out.size() == 1);
  CHECK(out[0].start == 0x2000);
  CHECK(out[0].end == 0x2030);
}

TEST_CASE("memory filter merges overlapping selectors") {
  w1rewind::rewind_config::memory_options options{};
  options.filters = {
      w1rewind::rewind_config::memory_filter_kind::ranges,
      w1rewind::rewind_config::memory_filter_kind::stack_window,
  };
  options.ranges = {
      {0x1000, 0x1100},
  };
  w1rewind::memory_filter filter(options);

  std::vector<w1rewind::stack_window_segment> segments = {
      {0x1080, 0x40},
  };

  auto out = filter.filter(0x1050, 0x100, segments);
  REQUIRE(out.size() == 1);
  CHECK(out[0].start == 0x1050);
  CHECK(out[0].end == 0x1100);
}

TEST_CASE("memory filter splits access across disjoint segments") {
  w1rewind::rewind_config::memory_options options{};
  options.filters = {w1rewind::rewind_config::memory_filter_kind::stack_window};
  w1rewind::memory_filter filter(options);

  std::vector<w1rewind::stack_window_segment> segments = {
      {0x2000, 0x10},
      {0x2020, 0x10},
  };

  auto out = filter.filter(0x1FF0, 0x50, segments);
  REQUIRE(out.size() == 2);
  CHECK(out[0].start == 0x2000);
  CHECK(out[0].end == 0x2010);
  CHECK(out[1].start == 0x2020);
  CHECK(out[1].end == 0x2030);
}
