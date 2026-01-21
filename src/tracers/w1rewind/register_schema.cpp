#include "register_schema.hpp"

#include <cstddef>

#include "w1runtime/register_capture.hpp"
#include "w1rewind/format/register_metadata.hpp"

namespace w1rewind {

void register_schema::clear() {
  names_.clear();
  specs_.clear();
}

void register_schema::update(const w1::util::register_state& regs, const w1::arch::arch_spec& arch) {
  names_ = regs.get_register_names();
  specs_.clear();
  specs_.reserve(names_.size());

  uint32_t pointer_size = arch.pointer_bits == 0 ? static_cast<uint32_t>(sizeof(void*)) : arch.pointer_bits / 8;
  for (size_t i = 0; i < names_.size(); ++i) {
    specs_.push_back(w1::rewind::build_register_spec(arch, static_cast<uint16_t>(i), names_[i], pointer_size));
  }
}

} // namespace w1rewind
