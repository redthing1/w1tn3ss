#include "memory_view.hpp"

#include <algorithm>

#include "w1replay/modules/image_reader.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_state.hpp"

namespace w1replay {

replay_memory_view::replay_memory_view(
    const w1::rewind::replay_context* context, const w1::rewind::replay_state* state, image_reader* image_reader
)
    : context_(context), state_(state), image_reader_(image_reader) {}

void replay_memory_view::set_state(const w1::rewind::replay_state* state) { state_ = state; }

w1::rewind::memory_read replay_memory_view::read(uint32_t space_id, uint64_t address, size_t size) {
  w1::rewind::memory_read out;
  if (state_) {
    out = state_->read_memory(space_id, address, size);
  } else {
    out.bytes.assign(size, std::byte{0});
    out.known.assign(size, 0);
  }

  if (!context_ || !image_reader_ || size == 0) {
    return out;
  }

  auto image_bytes = image_reader_->read_address_bytes(*context_, address, size, space_id);
  if (!image_bytes.error.empty()) {
    return out;
  }

  size_t limit = std::min({size, image_bytes.bytes.size(), image_bytes.known.size()});
  for (size_t i = 0; i < limit; ++i) {
    if (out.known[i] == 0 && image_bytes.known[i]) {
      out.bytes[i] = image_bytes.bytes[i];
      out.known[i] = 1;
    }
  }

  return out;
}

} // namespace w1replay
