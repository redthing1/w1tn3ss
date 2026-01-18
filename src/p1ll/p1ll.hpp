#pragma once

#include <string>
#include <memory>

// engine public surface
#include "engine/result.hpp"
#include "engine/types.hpp"
#include "engine/pattern.hpp"
#include "engine/session.hpp"
#include "engine/platform/platform.hpp"

// utilities
#include "utils/hex_utils.hpp"
#include "utils/hex_pattern.hpp"
#include "utils/file_utils.hpp"

namespace p1ll {

/**
 * @brief check if scripting support is compiled in
 */
inline bool has_scripting_support() {
#ifdef P1LL_HAS_SCRIPTING
  return true;
#else
  return false;
#endif
}

} // namespace p1ll
