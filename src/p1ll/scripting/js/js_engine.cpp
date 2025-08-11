#include "js_engine.hpp"
#include "js_bindings.hpp"
#include <redlog.hpp>
#include <jnjs/jnjs.h>

namespace p1ll::scripting::js {

// helper function to extract cure_result from js object
cure_result extract_cure_result(const jnjs::value& js_result) {
  cure_result result;

  if (js_result["success"].is<bool>()) {
    result.success = js_result["success"].as<bool>();
  } else {
    result.success = true;
  }

  if (js_result["patches_applied"].is<int>()) {
    result.patches_applied = js_result["patches_applied"].as<int>();
  }

  if (js_result["patches_failed"].is<int>()) {
    result.patches_failed = js_result["patches_failed"].as<int>();
  }

  return result;
}

js_engine::js_engine() {
  auto log = redlog::get_logger("p1ll.js_engine");
  log.inf("initializing js engine");
}

cure_result js_engine::execute_script(const context& context, const std::string& script_content) {
  auto log = redlog::get_logger("p1ll.js_engine");
  log.inf("executing js script for dynamic patching");

  try {
    auto js_ctx = jnjs::runtime::new_context();
    setup_p1ll_js_bindings(js_ctx, context);
    js_ctx.eval(script_content);

    auto cure_fn = js_ctx.eval("cure");
    if (cure_fn.is<jnjs::function>()) {
      log.dbg("executing cure() function");
      auto cure_result_value = cure_fn.as<jnjs::function>();
      auto js_result = cure_result_value();

      // try to extract result as object properties
      cure_result result;

      return extract_cure_result(js_result);
    } else {
      log.err("no cure() function found in script");
      cure_result result;
      result.add_error("script must define a cure() function");
      return result;
    }

  } catch (const std::exception& e) {
    log.err("js execution failed", redlog::field("error", e.what()));
    cure_result result;
    result.add_error("js execution error: " + std::string(e.what()));
    return result;
  }
}

cure_result js_engine::execute_script_content_with_buffer(
    const context& context, const std::string& script_content, std::vector<uint8_t>& buffer_data
) {
  auto log = redlog::get_logger("p1ll.js_engine");
  log.inf("executing js script for static patching with buffer");

  try {
    auto js_ctx = jnjs::runtime::new_context();
    setup_p1ll_js_bindings_with_buffer(js_ctx, context, buffer_data);
    js_ctx.eval(script_content);

    auto cure_fn = js_ctx.eval("cure");
    if (cure_fn.is<jnjs::function>()) {
      log.dbg("executing cure() function");
      auto cure_result_value = cure_fn.as<jnjs::function>();
      auto js_result = cure_result_value();

      // try to extract result as object properties
      cure_result result;

      return extract_cure_result(js_result);
    } else {
      log.err("no cure() function found in script");
      cure_result result;
      result.add_error("script must define a cure() function");
      return result;
    }

  } catch (const std::exception& e) {
    log.err("js execution with buffer failed", redlog::field("error", e.what()));
    cure_result result;
    result.add_error("js execution error: " + std::string(e.what()));
    return result;
  }
}

} // namespace p1ll::scripting::js