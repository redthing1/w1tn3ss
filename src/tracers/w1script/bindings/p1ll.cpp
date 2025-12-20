#include "p1ll.hpp"

#include <p1ll/scripting/lua/lua_bindings.hpp>
#include <redlog.hpp>

namespace w1::tracers::script::bindings {

void setup_p1ll_bindings(sol::state& lua, sol::table& w1_module, runtime::script_context& context) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up p1ll bindings");

  auto p1_context = context.p1ll_context();
  if (!p1_context) {
    logger.err("p1ll context is null");
    return;
  }

  sol::table p1ll_table = lua.create_table();
  p1ll::scripting::bindings::setup_core_types(lua, p1ll_table);
  p1ll::scripting::bindings::setup_signature_api(lua, p1ll_table);
  p1ll::scripting::bindings::setup_patch_api(lua, p1ll_table);
  p1ll::scripting::bindings::setup_auto_cure_api(lua, p1ll_table, *p1_context);
  p1ll::scripting::bindings::setup_manual_api(lua, p1ll_table);
  p1ll::scripting::bindings::setup_utilities(lua, p1ll_table);

  w1_module["p1ll"] = p1ll_table;
}

} // namespace w1::tracers::script::bindings
