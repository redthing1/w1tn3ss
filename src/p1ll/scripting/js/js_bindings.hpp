#pragma once

// javascript bindings stub - header-only placeholder
// this file exists as a placeholder for future javascript engine implementation

#include <redlog.hpp>

namespace p1ll::scripting::js {

// placeholder - no actual bindings implemented
inline void setup_js_bindings_placeholder() {
  auto log = redlog::get_logger("p1ll.js_bindings");
  log.wrn("javascript bindings not implemented - placeholder only");
}

} // namespace p1ll::scripting::js