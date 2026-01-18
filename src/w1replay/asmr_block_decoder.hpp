#pragma once

#include <cstdint>
#include <string>

#include "w1tn3ss/runtime/rewind/replay_decode.hpp"

namespace w1replay {

struct module_source;

class asmr_block_decoder final : public w1::rewind::replay_block_decoder {
public:
  ~asmr_block_decoder();

  void set_module_source(module_source* module_source) { module_source_ = module_source; }

  bool decode_block(
      const w1::rewind::replay_context& context,
      uint64_t module_id,
      uint64_t module_offset,
      uint32_t size,
      w1::rewind::replay_decoded_block& out,
      std::string& error
  ) override;

private:
  module_source* module_source_ = nullptr;
};

bool asmr_decoder_available();

} // namespace w1replay
