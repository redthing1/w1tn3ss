#include "sig.hpp"

#include <iostream>
#include <span>

#include <redlog.hpp>

#include "p1ll/engine/session.hpp"
#include "p1ll/utils/file_utils.hpp"
#include "p1ll/utils/hex_utils.hpp"

namespace p1llx::commands {

int sig_command(const sig_request& request) {
  auto log = redlog::get_logger("p1llx.sig");

  if (request.pattern.empty()) {
    log.err("signature pattern required");
    std::cerr << "error: signature pattern is required" << std::endl;
    return 1;
  }

  if (request.input_file.empty()) {
    log.err("input file required");
    std::cerr << "error: input file is required" << std::endl;
    return 1;
  }

  auto file_data = p1ll::utils::read_file(request.input_file);
  if (!file_data.has_value()) {
    log.err("failed to read input file", redlog::field("path", request.input_file));
    std::cerr << "error: could not read input file: " << request.input_file << std::endl;
    return 1;
  }

  auto session = p1ll::engine::session::for_buffer(std::span<uint8_t>(*file_data));
  p1ll::engine::scan_options options;
  options.single = request.single;

  auto results = session.scan(request.pattern, options);
  if (!results.ok()) {
    log.err("signature scan failed", redlog::field("error", results.status.message));
    std::cerr << "error: " << results.status.message << std::endl;
    return 1;
  }

  if (results.value.empty()) {
    log.err("signature not found", redlog::field("pattern", request.pattern));
    std::cerr << "error: signature not found" << std::endl;
    return 1;
  }

  std::cout << "matches: " << results.value.size() << std::endl;
  for (const auto& match : results.value) {
    std::cout << p1ll::utils::format_address(match.address);
    if (!match.region_name.empty()) {
      std::cout << " " << match.region_name;
    }
    std::cout << "\n";
  }

  return 0;
}

} // namespace p1llx::commands
