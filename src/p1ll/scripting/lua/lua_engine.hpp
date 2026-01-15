#pragma once

#include "../script_engine.hpp"
#include <sol/sol.hpp>
#include <string>
#include <memory>

namespace p1ll::scripting::lua {

// lua script execution engine
class lua_engine : public IScriptEngine {
public:
  lua_engine();
  ~lua_engine() = default;

  // execute script with an active session
  engine::result<engine::apply_report> execute_script(
      engine::session& session, const std::string& script_content
  ) override;

  // get lua state for advanced usage
  sol::state& get_lua_state() { return lua_; }

private:
  sol::state lua_;

  void setup_lua_environment();
  void setup_logging_integration();

  // execute cure function from loaded script
  engine::result<engine::apply_report> call_cure_function();
};

} // namespace p1ll::scripting::lua
