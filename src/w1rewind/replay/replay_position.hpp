#pragma once

#include <optional>
#include <string>

#include "block_decoder.hpp"
#include "flow_types.hpp"
#include "replay_context.hpp"

namespace w1::rewind {

enum class position_kind { block, instruction };

struct replay_position {
  flow_step flow{};
  position_kind kind = position_kind::block;
  std::optional<flow_step> instruction;
};

class position_normalizer {
public:
  explicit position_normalizer(block_decoder* decoder) : decoder_(decoder) {}

  bool normalize(const replay_context& context, replay_position& pos, bool forward_bias, std::string& error) const;

private:
  block_decoder* decoder_ = nullptr;
};

} // namespace w1::rewind
