#include "signature_scanning.hpp"
#include <p1ll/scripting/lua_bindings.hpp>
#include <p1ll/core/context.hpp>
#include <redlog.hpp>

namespace w1::tracers::script::bindings {

void setup_signature_scanning(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up signature scanning functions");

  // setup p1ll bindings in the lua state
  logger.dbg("registering p1ll lua bindings");
  auto context = p1ll::context::create_dynamic();
  p1ll::scripting::setup_p1ll_bindings(lua, *context);

  // note: we just directly use p1ll, so it's the script's responsibility
  // to compose the p1.search_signature() and w1.hook_addr() calls

  logger.dbg("signature scanning functions registered");
}

} // namespace w1::tracers::script::bindings