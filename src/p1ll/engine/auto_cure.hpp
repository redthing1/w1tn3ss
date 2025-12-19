#pragma once

#include "core/types.hpp"
#include "core/context.hpp"
#include "address_space.hpp"
#include <memory>

namespace p1ll::engine {

// auto-cure class constructed with context
class auto_cure {
public:
  explicit auto_cure(const context& ctx);
  ~auto_cure() = default;

  // dynamic process patching
  cure_result execute_dynamic(const cure_config& config);

  // static buffer patching
  cure_result execute_static(std::vector<uint8_t>& buffer_data, const cure_config& config);

private:
  const context& context_;
  std::unique_ptr<address_space> address_space_;
  cure_result execute_with_space(address_space& space, const cure_config& config);

};

} // namespace p1ll::engine
