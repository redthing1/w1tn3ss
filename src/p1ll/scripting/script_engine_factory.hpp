#pragma once

#include "script_engine.hpp"
#include <memory>
#include <vector>
#include <string>

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

  // get list of supported script engines in this build
  static std::vector<ScriptEngineType> get_supported_engines();

  // get file extensions for supported engines
  static std::vector<std::string> get_supported_extensions();

  // check if an engine type is supported in this build
  static bool is_engine_supported(ScriptEngineType engine_type);
};

} // namespace p1ll::scripting