#include "doctest/doctest.hpp"

#include "w1rewind/replay/history_window.hpp"

namespace {

w1::rewind::history_window::entry make_entry(uint64_t sequence) {
  w1::rewind::history_window::entry entry{};
  entry.step.thread_id = 1;
  entry.step.sequence = sequence;
  entry.location.chunk_index = static_cast<uint32_t>(sequence);
  entry.location.record_offset = 0;
  return entry;
}

void push_entry(w1::rewind::history_window& window, uint64_t sequence) {
  auto entry = make_entry(sequence);
  window.push(entry.step, entry.location);
}

} // namespace

TEST_CASE("w1rewind history_window pushes and navigates") {
  w1::rewind::history_window window(3);

  push_entry(window, 0);
  push_entry(window, 1);
  push_entry(window, 2);

  CHECK_FALSE(window.empty());
  CHECK(window.current().step.sequence == 2);
  CHECK(window.has_past());
  CHECK_FALSE(window.has_future());

  REQUIRE(window.rewind());
  CHECK(window.current().step.sequence == 1);
  CHECK(window.has_past());
  CHECK(window.has_future());

  REQUIRE(window.forward());
  CHECK(window.current().step.sequence == 2);
}

TEST_CASE("w1rewind history_window resizes while keeping current") {
  w1::rewind::history_window window(4);

  push_entry(window, 0);
  push_entry(window, 1);
  push_entry(window, 2);
  push_entry(window, 3);

  REQUIRE(window.rewind());
  REQUIRE(window.rewind());
  CHECK(window.current().step.sequence == 1);

  window.resize(2);
  CHECK(window.size() == 2);
  CHECK(window.current().step.sequence == 1);
  CHECK_FALSE(window.has_past());
  CHECK(window.has_future());
}

TEST_CASE("w1rewind history_window enforces minimum capacity") {
  w1::rewind::history_window window(0);
  CHECK(window.capacity() == 1);

  window.resize(0);
  CHECK(window.capacity() == 1);
}
