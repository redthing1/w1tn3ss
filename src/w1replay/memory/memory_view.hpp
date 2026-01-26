#pragma once

#include <cstddef>
#include <cstdint>

#include "w1rewind/replay/memory_store.hpp"

namespace w1::rewind {
struct replay_context;
class replay_state;
} // namespace w1::rewind

namespace w1replay {

class image_reader;

class memory_view {
public:
  virtual ~memory_view() = default;
  virtual w1::rewind::memory_read read(uint32_t space_id, uint64_t address, size_t size) = 0;
};

class replay_memory_view final : public memory_view {
public:
  replay_memory_view(
      const w1::rewind::replay_context* context, const w1::rewind::replay_state* state, image_reader* image_reader
  );

  void set_state(const w1::rewind::replay_state* state);
  w1::rewind::memory_read read(uint32_t space_id, uint64_t address, size_t size) override;

private:
  const w1::rewind::replay_context* context_ = nullptr;
  const w1::rewind::replay_state* state_ = nullptr;
  image_reader* image_reader_ = nullptr;
};

} // namespace w1replay
