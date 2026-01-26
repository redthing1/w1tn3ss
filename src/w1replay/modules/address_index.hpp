#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "w1rewind/replay/replay_context.hpp"

namespace w1::rewind {
class mapping_state;
} // namespace w1::rewind

namespace w1replay {

struct image_address_match {
  const w1::rewind::mapping_record* mapping = nullptr;
  const w1::rewind::image_record* image = nullptr;
  uint64_t image_offset = 0;
  uint64_t range_start = 0;
  uint64_t range_end = 0;
};

class image_address_index {
public:
  explicit image_address_index(
      const w1::rewind::replay_context& context, const w1::rewind::mapping_state* mappings = nullptr
  );

  std::optional<image_address_match> find(uint64_t address, uint64_t size, uint32_t space_id = 0) const;

private:
  const w1::rewind::replay_context& context_;
  const w1::rewind::mapping_state* mappings_ = nullptr;
};

} // namespace w1replay
