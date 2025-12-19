#pragma once

#include "address_space.hpp"
#include "core/types.hpp"
#include <optional>
#include <vector>

namespace p1ll::engine {

class signature_scanner {
public:
  explicit signature_scanner(address_space& space);

  std::optional<std::vector<search_result>> scan(
      const compiled_signature& signature, const signature_query_filter& filter
  );
  std::optional<uint64_t> scan_single(const compiled_signature& signature, const signature_query_filter& filter);

private:
  address_space& space_;
};

} // namespace p1ll::engine
