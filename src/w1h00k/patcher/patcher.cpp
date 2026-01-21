#include "w1h00k/patcher.hpp"

namespace w1::h00k {

bool code_patcher::write(void* address, const uint8_t* bytes, size_t size) {
  (void)address;
  (void)bytes;
  (void)size;
  return false;
}

bool code_patcher::restore(void* address, const uint8_t* bytes, size_t size) {
  (void)address;
  (void)bytes;
  (void)size;
  return false;
}

} // namespace w1::h00k
