#pragma once

#include "address_space.hpp"
#include "core/types.hpp"
#include <string>
#include <vector>

namespace p1ll::engine {

struct patch_plan_entry {
  patch_decl decl;
  uint64_t address = 0;
  compiled_patch patch;
  std::string description;
};

struct patch_execution_result {
  bool success = false;
  size_t bytes_written = 0;
  std::vector<std::string> error_messages;

  void add_error(const std::string& error) { error_messages.push_back(error); }
  bool has_errors() const { return !error_messages.empty(); }
};

class patch_executor {
public:
  explicit patch_executor(address_space& space);

  patch_execution_result apply(const patch_plan_entry& entry);

private:
  address_space& space_;
};

} // namespace p1ll::engine
