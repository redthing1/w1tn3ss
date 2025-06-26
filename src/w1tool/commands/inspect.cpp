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

    // future: implement binary analysis logic
    log.info("w1tn3ss library info");
    w1::w1tn3ss::print_info();
    log.warn("binary analysis not yet implemented");
  } else {
    log.error("binary path required for inspection");
    return 1;
  }

  return 0;
}

} // namespace w1tool::commands