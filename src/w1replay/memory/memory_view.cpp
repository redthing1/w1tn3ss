#include "memory_view.hpp"

#include <algorithm>

#include "w1replay/modules/image_reader.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_state.hpp"

namespace w1replay {

replay_memory_view::replay_memory_view(
    const w1::rewind::replay_context* context, const w1::rewind::replay_state* state,
    module_image_reader* module_reader
)
    : context_(context), state_(state), module_reader_(module_reader) {}

void replay_memory_view::set_state(const w1::rewind::replay_state* state) { state_ = state; }

w1::rewind::memory_read replay_memory_view::read(uint64_t address, size_t size) {
  w1::rewind::memory_read out;
  if (state_) {
    out = state_->read_memory(address, size);
  } else {
    out.bytes.assign(size, std::byte{0});
    out.known.assign(size, 0);
  }

  if (!context_ || !module_reader_ || size == 0) {
    return out;
  }

  auto module_bytes = module_reader_->read_address_bytes(*context_, address, size);
  if (!module_bytes.error.empty()) {
    return out;
  }

  size_t limit = std::min({size, module_bytes.bytes.size(), module_bytes.known.size()});
  for (size_t i = 0; i < limit; ++i) {
    if (out.known[i] == 0 && module_bytes.known[i]) {
      out.bytes[i] = module_bytes.bytes[i];
      out.known[i] = 1;
    }
  }

  return out;
}

} // namespace w1replay
