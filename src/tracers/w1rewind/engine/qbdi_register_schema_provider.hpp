#pragma once

#include "register_schema_provider.hpp"

namespace w1rewind {

class qbdi_register_schema_provider final : public register_schema_provider {
public:
  bool build_register_schema(
      const w1::rewind::arch_descriptor_record& arch, std::vector<w1::rewind::register_spec>& out,
      std::string& error
  ) const override;
};

} // namespace w1rewind
