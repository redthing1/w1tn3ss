#pragma once

#include <cstddef>
#include <cstdint>

namespace w1::h00k {

class code_patcher {
public:
  bool write(void* address, const uint8_t* bytes, size_t size);
  bool restore(void* address, const uint8_t* bytes, size_t size);
};

class data_patcher {
public:
  bool write(void* address, const uint8_t* bytes, size_t size);
  bool restore(void* address, const uint8_t* bytes, size_t size);
};

} // namespace w1::h00k
