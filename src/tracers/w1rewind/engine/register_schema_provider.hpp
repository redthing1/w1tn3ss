#pragma once

#include <string>
#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1rewind {

class register_schema_provider {
public:
  virtual ~register_schema_provider() = default;

  virtual bool build_register_schema(
      const w1::rewind::arch_descriptor_record& arch, std::vector<w1::rewind::register_spec>& out, std::string& error
  ) const = 0;
};

} // namespace w1rewind
