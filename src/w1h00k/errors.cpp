#include "w1h00k/errors.hpp"

namespace w1::h00k {

const char* to_string(hook_error error) {
  switch (error) {
    case hook_error::ok:
      return "ok";
    case hook_error::unsupported:
      return "unsupported";
    case hook_error::invalid_target:
      return "invalid_target";
    case hook_error::relocation_failed:
      return "relocation_failed";
    case hook_error::near_alloc_failed:
      return "near_alloc_failed";
    case hook_error::patch_failed:
      return "patch_failed";
    case hook_error::already_hooked:
      return "already_hooked";
    case hook_error::not_found:
      return "not_found";
    case hook_error::access_denied:
      return "access_denied";
  }
  return "unknown";
}

} // namespace w1::h00k
