#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>

#include "w1tn3ss/runtime/rewind/replay_decode.hpp"

#if defined(WITNESS_LIEF_ENABLED)
#include <LIEF/LIEF.hpp>
#endif

namespace w1replay {

class asmr_block_decoder final : public w1::rewind::replay_block_decoder {
public:
  ~asmr_block_decoder();

  bool decode_block(
      const w1::rewind::replay_context& context,
      uint64_t module_id,
      uint64_t module_offset,
      uint32_t size,
      w1::rewind::replay_decoded_block& out,
      std::string& error
  ) override;

private:
#if defined(WITNESS_LIEF_ENABLED)
  struct module_entry {
    std::string path;
    std::unique_ptr<LIEF::Binary> binary;
  };

  std::unordered_map<uint64_t, module_entry> modules_;
#endif
};

bool asmr_decoder_available();

} // namespace w1replay
