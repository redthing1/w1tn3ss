#pragma once

#ifdef WITNESS_SCRIPT_ENABLED

#include "../core/types.hpp"
#include <sol/sol.hpp>
#include <string>
#include <memory>

namespace p1ll::scripting {

// lua script execution engine
class lua_api {
public:
  lua_api();
  ~lua_api() = default;

  // execute cure script from file
  core::cure_result execute_cure_script(const std::string& script_path);

  // execute cure script from string content
  core::cure_result execute_script_content(const std::string& script_content);

  // execute static cure on file
  core::cure_result execute_static_cure(
      const std::string& script_path, const std::string& input_file, const std::string& output_file
  );

  // get lua state for advanced usage
  sol::state& get_lua_state() { return lua_; }

private:
  sol::state lua_;

  void setup_lua_environment();
  void setup_logging_integration();

  // execute cure function from loaded script
  core::cure_result call_cure_function();
};

} // namespace p1ll::scripting

#endif // WITNESS_SCRIPT_ENABLED