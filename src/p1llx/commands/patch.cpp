#include "patch.hpp"
#include <p1ll/p1ll.hpp>
#include <redlog.hpp>
#include <fstream>
#include <iostream>

namespace p1llx::commands {

int patch(
    const std::string& address_str, const std::string& replace_data, const std::string& input_file,
    const std::string& output_file
) {

  auto log = redlog::get_logger("p1llx.commands.patch");

  log.inf(
      "applying manual patch", redlog::field("address", address_str), redlog::field("replace", replace_data),
      redlog::field("input", input_file), redlog::field("output", output_file)
  );

  try {
    // parse address (support both 0x prefix and plain hex)
    uint64_t address;
    if (address_str.substr(0, 2) == "0x" || address_str.substr(0, 2) == "0X") {
      address = std::stoull(address_str, nullptr, 16);
    } else {
      address = std::stoull(address_str, nullptr, 16);
    }

    // validate hex pattern
    if (!p1ll::utils::is_valid_hex_pattern(replace_data)) {
      log.err("invalid replacement hex pattern", redlog::field("pattern", replace_data));
      std::cerr << "error: invalid hex pattern: " << replace_data << std::endl;
      return 1;
    }

    // read input file
    std::ifstream input(input_file, std::ios::binary | std::ios::ate);
    if (!input.is_open()) {
      log.err("failed to open input file", redlog::field("path", input_file));
      std::cerr << "error: could not open input file: " << input_file << std::endl;
      return 1;
    }

    auto file_size = input.tellg();
    input.seekg(0, std::ios::beg);

    std::vector<uint8_t> file_data(static_cast<size_t>(file_size));
    input.read(reinterpret_cast<char*>(file_data.data()), file_size);
    input.close();

    if (!input) {
      log.err("failed to read input file", redlog::field("path", input_file));
      std::cerr << "error: failed to read input file: " << input_file << std::endl;
      return 1;
    }

    // compile patch
    auto parsed_patch = p1ll::engine::parse_patch(replace_data);
    if (!parsed_patch.ok()) {
      log.err("failed to compile patch", redlog::field("pattern", replace_data));
      std::cerr << "error: failed to compile patch pattern: " << replace_data << std::endl;
      return 1;
    }

    // check bounds
    if (address + parsed_patch.value.bytes.size() > file_data.size()) {
      log.err(
          "patch would exceed file bounds", redlog::field("address", address),
          redlog::field("patch_size", parsed_patch.value.bytes.size()), redlog::field("file_size", file_data.size())
      );
      std::cerr << "error: patch would exceed file bounds" << std::endl;
      return 1;
    }

    // apply patch
    size_t bytes_patched = 0;
    for (size_t i = 0; i < parsed_patch.value.bytes.size(); ++i) {
      if (parsed_patch.value.mask[i]) {
        file_data[address + i] = parsed_patch.value.bytes[i];
        bytes_patched++;
      }
    }

    // write output file
    std::ofstream output(output_file, std::ios::binary);
    if (!output.is_open()) {
      log.err("failed to create output file", redlog::field("path", output_file));
      std::cerr << "error: could not create output file: " << output_file << std::endl;
      return 1;
    }

    output.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
    output.close();

    if (!output) {
      log.err("failed to write output file", redlog::field("path", output_file));
      std::cerr << "error: failed to write output file: " << output_file << std::endl;
      return 1;
    }

    log.inf(
        "patch applied successfully", redlog::field("bytes_patched", bytes_patched), redlog::field("address", address)
    );

    std::cout << "patch applied successfully" << std::endl;
    std::cout << "bytes patched: " << bytes_patched << " at address 0x" << std::hex << address << std::endl;

    return 0;

  } catch (const std::exception& e) {
    log.err("patch failed", redlog::field("error", e.what()));
    std::cerr << "error: " << e.what() << std::endl;
    return 1;
  }
}

} // namespace p1llx::commands
