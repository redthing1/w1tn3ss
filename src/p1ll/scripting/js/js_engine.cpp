#include "js_engine.hpp"
#include "js_bindings.hpp"
#include <jnjs/jnjs.h>
#include <redlog.hpp>

namespace p1ll::scripting::js {

namespace {

engine::apply_report extract_apply_report(const jnjs::value& js_result) {
  engine::apply_report report;

  if (js_result.is<apply_report_wrapper*>()) {
    auto wrapper = js_result.as<apply_report_wrapper*>();
    if (wrapper) {
      report.success = wrapper->get_success();
      report.applied = wrapper->get_applied();
      report.failed = wrapper->get_failed();
      report.diagnostics = wrapper->get_statuses();
      return report;
    }
  }

  if (js_result["success"].is<bool>()) {
    report.success = js_result["success"].as<bool>();
  }
  if (js_result["applied"].is<int>()) {
    report.applied = static_cast<size_t>(js_result["applied"].as<int>());
  }
  if (js_result["failed"].is<int>()) {
    report.failed = static_cast<size_t>(js_result["failed"].as<int>());
  }

  return report;
}

engine::result<engine::apply_report> execute_cure_script_impl(
    jnjs::context& js_ctx, const std::string& script_content, const std::string& log_context
) {
  auto log = redlog::get_logger("p1ll.js_engine");

  try {
    js_ctx.eval(script_content);

    auto cure_fn = js_ctx.eval("cure");
    if (!cure_fn.is<jnjs::function>()) {
      log.err("no cure() function found in script", redlog::field("context", log_context));
      return engine::error_result<engine::apply_report>(
          engine::error_code::invalid_argument, "script must define a callable cure() function"
      );
    }

    log.dbg("executing cure() function", redlog::field("context", log_context));
    auto js_result = cure_fn.as<jnjs::function>()();
    auto report = extract_apply_report(js_result);
    log.inf(
        "cure completed", redlog::field("success", report.success), redlog::field("applied", report.applied),
        redlog::field("failed", report.failed)
    );
    return engine::ok_result(report);
  } catch (const std::runtime_error& e) {
    log.err("js runtime error", redlog::field("error", e.what()), redlog::field("context", log_context));
    return engine::error_result<engine::apply_report>(
        engine::error_code::internal_error, "js runtime error: " + std::string(e.what())
    );
  } catch (const std::bad_alloc& e) {
    log.err("js memory allocation failed", redlog::field("error", e.what()), redlog::field("context", log_context));
    return engine::error_result<engine::apply_report>(
        engine::error_code::internal_error, "js out of memory: " + std::string(e.what())
    );
  } catch (const std::exception& e) {
    log.err("js execution failed", redlog::field("error", e.what()), redlog::field("context", log_context));
    return engine::error_result<engine::apply_report>(
        engine::error_code::internal_error, "js execution error: " + std::string(e.what())
    );
  }
}

} // namespace

js_engine::js_engine() {
  auto log = redlog::get_logger("p1ll.js_engine");
  log.inf("initializing js engine");
}

engine::result<engine::apply_report> js_engine::execute_script(
    engine::session& session, const std::string& script_content
) {
  auto log = redlog::get_logger("p1ll.js_engine");
  log.inf("executing js script", redlog::field("mode", session.is_dynamic() ? "dynamic" : "static"));

  auto js_ctx = jnjs::runtime::new_context();
  setup_p1ll_js_bindings(js_ctx, session);
  return execute_cure_script_impl(js_ctx, script_content, session.is_dynamic() ? "dynamic" : "static");
}

} // namespace p1ll::scripting::js
