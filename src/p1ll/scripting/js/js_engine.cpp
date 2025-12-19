#include "js_engine.hpp"
#include "js_bindings.hpp"
#include <redlog.hpp>
#include <jnjs/jnjs.h>

namespace p1ll::scripting::js {

// helper function to extract cure_result from js object
cure_result extract_cure_result(const jnjs::value& js_result) {
  cure_result result;

  if (js_result.is<cure_result_wrapper*>()) {
    auto wrapper = js_result.as<cure_result_wrapper*>();
    if (wrapper) {
      result.success = wrapper->get_success();
      result.patches_applied = wrapper->get_patches_applied();
      result.patches_failed = wrapper->get_patches_failed();
      result.error_messages = wrapper->get_error_messages();
      return result;
    }
  }

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

// helper function to execute cure function and common logic
cure_result execute_cure_script_impl(
    jnjs::context& js_ctx, const std::string& script_content, const std::string& log_context
) {
  auto log = redlog::get_logger("p1ll.js_engine");

  try {
    js_ctx.eval(script_content);

    auto cure_fn = js_ctx.eval("cure");
    if (cure_fn.is<jnjs::function>()) {
      log.dbg("executing cure() function");
      auto cure_result_value = cure_fn.as<jnjs::function>();
      auto js_result = cure_result_value();
      return extract_cure_result(js_result);
    } else {
      log.err("no cure() function found in script or function is not callable");
      cure_result result;
      result.add_error("script must define a callable cure() function that returns a result object");
      return result;
    }

  } catch (const std::runtime_error& e) {
    log.err("js runtime error", redlog::field("error", e.what()), redlog::field("context", log_context));
    cure_result result;
    result.add_error("js runtime error: " + std::string(e.what()));
    return result;
  } catch (const std::bad_alloc& e) {
    log.err("js memory allocation failed", redlog::field("error", e.what()), redlog::field("context", log_context));
    cure_result result;
    result.add_error("js out of memory: " + std::string(e.what()));
    return result;
  } catch (const std::exception& e) {
    log.err("js execution failed", redlog::field("error", e.what()), redlog::field("context", log_context));
    cure_result result;
    result.add_error("js execution error: " + std::string(e.what()));
    return result;
  }
}

js_engine::js_engine() {
  auto log = redlog::get_logger("p1ll.js_engine");
  log.inf("initializing js engine");
}

cure_result js_engine::execute_script(const context& context, const std::string& script_content) {
  auto log = redlog::get_logger("p1ll.js_engine");
  log.inf("executing js script for dynamic patching");

  auto js_ctx = jnjs::runtime::new_context();
  setup_p1ll_js_bindings(js_ctx, context);
  return execute_cure_script_impl(js_ctx, script_content, "dynamic_patching");
}

cure_result js_engine::execute_script_content_with_buffer(
    const context& context, const std::string& script_content, std::vector<uint8_t>& buffer_data
) {
  auto log = redlog::get_logger("p1ll.js_engine");
  log.inf("executing js script for static patching with buffer");

  auto js_ctx = jnjs::runtime::new_context();
  setup_p1ll_js_bindings_with_buffer(js_ctx, context, buffer_data);
  return execute_cure_script_impl(js_ctx, script_content, "static_patching_with_buffer");
}

} // namespace p1ll::scripting::js
