#include "inspect.hpp"
#include "w1tn3ss.hpp"
#include <redlog/redlog.hpp>

namespace w1tool::commands {

int inspect(args::ValueFlag<std::string>& binary_flag) {

  auto log = redlog::get_logger("w1tool.inspect");

  log.info("binary inspection starting");

  // get arguments
  if (binary_flag) {
    std::string binary_path = args::get(binary_flag);
    log.info("target binary specified", redlog::field("binary_path", binary_path));

    // future: initialize w1tn3ss engine and analyze binary
    w1::w1tn3ss engine;
    if (engine.initialize()) {
      log.debug("analysis engine ready for binary inspection");
      // todo: implement binary analysis logic
      log.warn("binary analysis not yet implemented");
      engine.shutdown();
    } else {
      log.error("failed to initialize analysis engine");
      return 1;
    }
  } else {
    log.error("binary path required for inspection");
    return 1;
  }

  return 0;
}

} // namespace w1tool::commands