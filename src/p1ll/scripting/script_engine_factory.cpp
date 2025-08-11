#include "script_engine_factory.hpp"
#include <redlog.hpp>

// conditional includes based on compile-time configuration
#ifdef PILL_SCRIPT_ENGINE_JS
#include "js/js_engine.hpp"
#else
#include "lua/lua_engine.hpp"
#endif

namespace p1ll::scripting {

std::unique_ptr<IScriptEngine> ScriptEngineFactory::create() { return create(get_default_engine_type()); }

std::unique_ptr<IScriptEngine> ScriptEngineFactory::create(ScriptEngineType engine_type) {
  auto log = redlog::get_logger("p1ll.script_factory");

  switch (engine_type) {
#ifndef PILL_SCRIPT_ENGINE_JS
  case ScriptEngineType::LUA:
    log.dbg("creating lua script engine");
    return std::make_unique<lua::lua_engine>();
#endif

#ifdef PILL_SCRIPT_ENGINE_JS
  case ScriptEngineType::JAVASCRIPT:
    log.inf("creating js script engine");
    return std::make_unique<js::js_engine>();
#endif

  default:
    log.err("unsupported script engine type for this build configuration");
    return nullptr;
  }
}

ScriptEngineType ScriptEngineFactory::get_default_engine_type() {
  // compile-time engine selection based on configuration
#ifdef PILL_SCRIPT_ENGINE_JS
  return ScriptEngineType::JAVASCRIPT;
#else
  // default to lua
  return ScriptEngineType::LUA;
#endif
}

std::vector<ScriptEngineType> ScriptEngineFactory::get_supported_engines() {
  std::vector<ScriptEngineType> supported;

#ifndef PILL_SCRIPT_ENGINE_JS
  supported.push_back(ScriptEngineType::LUA);
#endif

#ifdef PILL_SCRIPT_ENGINE_JS
  supported.push_back(ScriptEngineType::JAVASCRIPT);
#endif

  return supported;
}

std::vector<std::string> ScriptEngineFactory::get_supported_extensions() {
  std::vector<std::string> extensions;

#ifndef PILL_SCRIPT_ENGINE_JS
  extensions.push_back(".lua");
#endif

#ifdef PILL_SCRIPT_ENGINE_JS
  extensions.push_back(".js");
#endif

  return extensions;
}

bool ScriptEngineFactory::is_engine_supported(ScriptEngineType engine_type) {
  switch (engine_type) {
#ifndef PILL_SCRIPT_ENGINE_JS
  case ScriptEngineType::LUA:
    return true;
#endif
#ifdef PILL_SCRIPT_ENGINE_JS
  case ScriptEngineType::JAVASCRIPT:
    return true;
#endif
  default:
    return false;
  }
}

} // namespace p1ll::scripting