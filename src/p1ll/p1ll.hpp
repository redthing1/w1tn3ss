#pragma once

#include <string>
#include <memory>

// core types and context
#include "core/types.hpp"
#include "core/context.hpp"

// main engines
#include "engine/auto_cure.hpp"
#include "engine/memory_scanner.hpp"
#include "engine/pattern_matcher.hpp"

// utilities
#include "utils/hex_utils.hpp"
#include "utils/hex_pattern.hpp"
#include "utils/file_utils.hpp"

// platform support
#include "core/platform.hpp"
#include "core/signature.hpp"

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
