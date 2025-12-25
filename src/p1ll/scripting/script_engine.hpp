#pragma once

#include "engine/result.hpp"
#include "engine/session.hpp"
#include "engine/types.hpp"
#include <string>
#include <memory>

namespace p1ll::scripting {

// abstract interface for script engines
class IScriptEngine {
public:
  virtual ~IScriptEngine() = default;

  // execute script with an active session (process or buffer)
  virtual engine::result<engine::apply_report> execute_script(
      engine::session& session, const std::string& script_content
  ) = 0;
};

// supported script engine types
enum class ScriptEngineType { LUA, JAVASCRIPT };

} // namespace p1ll::scripting
