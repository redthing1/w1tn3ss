#pragma once

namespace w1::instrument {

// return a reference to a heap-allocated state object that intentionally
// survives static destruction, to avoid shutdown-order teardown issues in preload
template <typename State> State& immortal_preload_state() {
  static State* state = new State();
  return *state;
}

} // namespace w1::instrument
