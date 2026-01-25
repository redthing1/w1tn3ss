#pragma once

#include <string>
#include <vector>

#include "w1base/arch_spec.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1::util {
class register_state;
}

namespace w1rewind {

class register_schema {
public:
  void clear();
  void update(const w1::util::register_state& regs, const w1::arch::arch_spec& arch);
  bool empty() const { return specs_.empty(); }

  const std::vector<std::string>& names() const { return names_; }
  const std::vector<w1::rewind::register_spec>& specs() const { return specs_; }

private:
  std::vector<std::string> names_;
  std::vector<w1::rewind::register_spec> specs_;
};

} // namespace w1rewind
