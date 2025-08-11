#pragma once

#include "core/types.hpp"
#include "core/context.hpp"
#include <string>
#include <memory>

namespace p1ll::scripting {

// abstract interface for script engines
class IScriptEngine {
public:
  virtual ~IScriptEngine() = default;

  // execute cure script from string content
  virtual cure_result execute_script(const context& context, const std::string& script_content) = 0;

  // execute cure script with explicit buffer (for static mode)
  virtual cure_result execute_script_content_with_buffer(
      const context& context, const std::string& script_content, std::vector<uint8_t>& buffer_data
  ) = 0;
};

// supported script engine types
enum class ScriptEngineType { LUA, JAVASCRIPT };

} // namespace p1ll::scripting