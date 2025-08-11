#include "js_engine.hpp"
#include <redlog.hpp>

namespace p1ll::scripting::js {

js_engine::js_engine() {
  auto log = redlog::get_logger("p1ll.js_engine");
  log.wrn("javascript engine is not implemented - only stub available");
}

cure_result js_engine::execute_script(const context& context, const std::string& script_content) {
  return create_not_implemented_error("execute_script");
}

cure_result js_engine::execute_script_content_with_buffer(
    const context& context, const std::string& script_content, std::vector<uint8_t>& buffer_data
) {
  return create_not_implemented_error("execute_script_content_with_buffer");
}

cure_result js_engine::create_not_implemented_error(const std::string& method_name) {
  auto log = redlog::get_logger("p1ll.js_engine");
  
  cure_result result;
  std::string error_msg = "javascript scripting engine is not implemented (method: " + method_name + ")";
  
  result.add_error(error_msg);
  log.err("javascript engine method called", redlog::field("method", method_name));
  
  return result;
}

} // namespace p1ll::scripting::js