#pragma once

#include "../script_engine.hpp"
#include <string>
#include <memory>

namespace p1ll::scripting::js {

// javascript script execution engine (stub implementation)
class js_engine : public IScriptEngine {
public:
  js_engine();
  ~js_engine() = default;

  // execute script with an active session
  engine::result<engine::apply_report> execute_script(
      engine::session& session, const std::string& script_content
  ) override;
};

} // namespace p1ll::scripting::js
