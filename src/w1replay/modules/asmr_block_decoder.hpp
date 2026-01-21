#pragma once

#include <cstdint>
#include <string>

#include "w1rewind/replay/replay_decode.hpp"

namespace w1replay {

class memory_view;

class asmr_block_decoder final : public w1::rewind::replay_block_decoder {
public:
  ~asmr_block_decoder();

  void set_memory_view(memory_view* view) { view_ = view; }

  bool decode_block(
      const w1::rewind::replay_context& context, const w1::rewind::flow_step& flow,
      w1::rewind::replay_decoded_block& out, std::string& error
  ) override;

private:
  memory_view* view_ = nullptr;
};

bool asmr_decoder_available();

} // namespace w1replay
