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

  // execute cure script from string content (throws not implemented error)
  cure_result execute_script(const context& context, const std::string& script_content) override;

  // execute cure script with explicit buffer (throws not implemented error)
  cure_result execute_script_content_with_buffer(
      const context& context, const std::string& script_content, std::vector<uint8_t>& buffer_data
  ) override;
};

} // namespace p1ll::scripting::js