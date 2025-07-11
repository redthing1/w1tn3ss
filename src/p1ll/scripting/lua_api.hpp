#pragma once

#include "core/types.hpp"
#include "core/context.hpp"
#include <sol/sol.hpp>
#include <string>
#include <memory>

namespace p1ll::scripting {

// lua script execution engine
class lua_api {
public:
  lua_api();
  ~lua_api() = default;

  // execute cure script from string content
  cure_result execute_script(const context& context, const std::string& script_content);

  // execute cure script with explicit buffer (for static mode)
  cure_result execute_script_content_with_buffer(
      const context& context, const std::string& script_content, std::vector<uint8_t>& buffer_data
  );

  // get lua state for advanced usage
  sol::state& get_lua_state() { return lua_; }

private:
  sol::state lua_;

  void setup_lua_environment();
  void setup_logging_integration();

  // execute cure function from loaded script
  cure_result call_cure_function();
};

} // namespace p1ll::scripting