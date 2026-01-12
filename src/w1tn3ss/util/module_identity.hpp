#pragma once

#include <string>

namespace w1::util {

struct module_identity {
  std::string name;
  std::string path;
};

module_identity module_identity_from_address(const void* address);

} // namespace w1::util
