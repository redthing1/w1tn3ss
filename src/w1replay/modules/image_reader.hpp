#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>

#include "module_image.hpp"

namespace w1::rewind {
struct module_record;
struct replay_context;
} // namespace w1::rewind

namespace w1replay {

using module_address_reader = std::function<bool(uint64_t address, std::span<std::byte> out, std::string& error)>;

class module_image_reader {
public:
  virtual ~module_image_reader() = default;

  virtual image_read_result read_module_bytes(
      const w1::rewind::module_record& module, uint64_t offset, size_t size
  ) = 0;
  virtual image_read_result read_address_bytes(
      const w1::rewind::replay_context& context, uint64_t address, size_t size
  ) = 0;
  virtual const image_layout* module_layout(const w1::rewind::module_record& module, std::string& error) = 0;
};

} // namespace w1replay
