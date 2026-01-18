#include "doctest/doctest.hpp"

#include "w1base/interval.hpp"

TEST_CASE("interval helpers validate ranges") {
  CHECK(w1::util::range_is_valid(0x1000, 0x2000) == true);
  CHECK(w1::util::range_is_valid(0x2000, 0x2000) == false);
  CHECK(w1::util::range_is_valid(0x3000, 0x2000) == false);
}

TEST_CASE("interval helpers compute size and containment") {
  CHECK(w1::util::range_size(0x1000, 0x1800) == 0x800);
  CHECK(w1::util::range_contains(0x1000, 0x2000, 0x1000) == true);
  CHECK(w1::util::range_contains(0x1000, 0x2000, 0x1fff) == true);
  CHECK(w1::util::range_contains(0x1000, 0x2000, 0x2000) == false);
}

TEST_CASE("interval helpers detect overlap") {
  CHECK(w1::util::range_overlaps(0x1000, 0x2000, 0x1800, 0x3000) == true);
  CHECK(w1::util::range_overlaps(0x1000, 0x2000, 0x2000, 0x3000) == false);
}

TEST_CASE("interval helpers compute end safely") {
  uint64_t end = 0;
  CHECK(w1::util::compute_end(0x1000, 0x200, &end));
  CHECK(end == 0x1200);

  uint64_t overflow_end = 0;
  CHECK(w1::util::compute_end(UINT64_MAX, 1, &overflow_end) == false);
}
