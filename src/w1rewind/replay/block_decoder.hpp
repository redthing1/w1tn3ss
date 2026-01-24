#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "flow_types.hpp"
#include "replay_context.hpp"

namespace w1::rewind {

struct decoded_instruction {
  uint64_t address = 0;
  uint32_t size = 0;
  std::vector<uint8_t> bytes;
};

struct decoded_block {
  uint64_t start = 0;
  uint32_t size = 0;
  std::vector<decoded_instruction> instructions;
};

class block_decoder {
public:
  virtual ~block_decoder() = default;

  virtual bool decode_block(
      const replay_context& context, const flow_step& flow, decoded_block& out, std::string& error
  ) = 0;
};

} // namespace w1::rewind
