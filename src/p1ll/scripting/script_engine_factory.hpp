#pragma once

#include "script_engine.hpp"
#include <memory>

namespace p1ll::scripting {

// factory for creating script engines
class ScriptEngineFactory {
public:
  // create script engine based on compile-time configuration
  static std::unique_ptr<IScriptEngine> create();
  
  // create script engine by explicit type (for testing)
  static std::unique_ptr<IScriptEngine> create(ScriptEngineType engine_type);
  
  // get the default engine type based on build configuration
  static ScriptEngineType get_default_engine_type();
};

} // namespace p1ll::scripting