#pragma once

#include <cstddef>
#include <cstdint>

#include "w1rewind/replay/memory_store.hpp"

namespace w1::rewind {
struct replay_context;
class replay_state;
}

namespace w1replay {

class module_image_reader;

class memory_view {
public:
  virtual ~memory_view() = default;
  virtual w1::rewind::memory_read read(uint64_t address, size_t size) = 0;
};

class replay_memory_view final : public memory_view {
public:
  replay_memory_view(
      const w1::rewind::replay_context* context, const w1::rewind::replay_state* state,
      module_image_reader* module_reader
  );

  void set_state(const w1::rewind::replay_state* state);
  w1::rewind::memory_read read(uint64_t address, size_t size) override;

private:
  const w1::rewind::replay_context* context_ = nullptr;
  const w1::rewind::replay_state* state_ = nullptr;
  module_image_reader* module_reader_ = nullptr;
};

} // namespace w1replay
