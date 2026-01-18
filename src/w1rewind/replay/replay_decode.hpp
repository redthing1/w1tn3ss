#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "replay_context.hpp"

namespace w1::rewind {

struct replay_decoded_instruction {
  uint32_t offset = 0;
  uint32_t size = 0;
  std::vector<uint8_t> bytes;
};

struct replay_decoded_block {
  uint64_t address = 0;
  uint32_t size = 0;
  std::vector<replay_decoded_instruction> instructions;
};

class replay_block_decoder {
public:
  virtual ~replay_block_decoder() = default;

  virtual bool decode_block(
      const replay_context& context,
      uint64_t address,
      uint32_t size,
      replay_decoded_block& out,
      std::string& error
  ) = 0;
};

} // namespace w1::rewind
