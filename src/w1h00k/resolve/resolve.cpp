#include "w1h00k/resolve/resolve.hpp"

namespace w1::h00k::resolve {

void* symbol_address(const char* symbol, const char* module) {
  (void)symbol;
  (void)module;
  return nullptr;
}

} // namespace w1::h00k::resolve
