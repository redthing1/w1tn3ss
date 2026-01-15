#include "patch.hpp"

#include <fstream>
#include <iostream>
#include <span>

#include <redlog.hpp>

#include <p1ll/p1ll.hpp>
#include "p1ll/engine/session.hpp"
#include "platform_utils.hpp"

namespace p1llx::commands {

namespace {

bool parse_offset_value(const std::string& value, int64_t& out) {
  if (value.empty()) {
    out = 0;
    return true;
  }

  try {
    size_t idx = 0;
    long long parsed = std::stoll(value, &idx, 0);
    if (idx != value.size()) {
      return false;
    }
    out = static_cast<int64_t>(parsed);
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

} // namespace

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

int patch_signature(
    const std::string& signature_pattern, const std::string& offset_str, const std::string& replace_data,
    const std::string& input_file, const std::string& output_file, const std::string& platform_override
) {
  auto log = redlog::get_logger("p1llx.commands.patch_sig");

  if (signature_pattern.empty()) {
    log.err("signature pattern required");
    std::cerr << "error: signature pattern is required" << std::endl;
    return 1;
  }

  int64_t offset = 0;
  if (!parse_offset_value(offset_str, offset)) {
    log.err("invalid patch offset", redlog::field("offset", offset_str));
    std::cerr << "error: invalid patch offset" << std::endl;
    return 1;
  }

  if (!p1ll::utils::is_valid_hex_pattern(signature_pattern)) {
    log.err("invalid signature pattern", redlog::field("pattern", signature_pattern));
    std::cerr << "error: invalid signature pattern" << std::endl;
    return 1;
  }

  if (!p1ll::utils::is_valid_hex_pattern(replace_data)) {
    log.err("invalid replacement hex pattern", redlog::field("pattern", replace_data));
    std::cerr << "error: invalid hex pattern: " << replace_data << std::endl;
    return 1;
  }

  auto file_data = p1ll::utils::read_file(input_file);
  if (!file_data.has_value()) {
    log.err("failed to read input file", redlog::field("path", input_file));
    std::cerr << "error: could not read input file: " << input_file << std::endl;
    return 1;
  }

  auto platform = resolve_platform(platform_override);
  if (!platform.ok()) {
    log.err("invalid platform override", redlog::field("error", platform.status.message));
    std::cerr << "error: invalid platform override" << std::endl;
    return 1;
  }

  auto buffer = std::span<uint8_t>(*file_data);
  auto session = platform_override.empty() ? p1ll::engine::session::for_buffer(buffer)
                                           : p1ll::engine::session::for_buffer(buffer, platform.value);

  p1ll::engine::signature_spec signature;
  signature.pattern = signature_pattern;
  signature.options.single = true;

  p1ll::engine::patch_spec patch_spec;
  patch_spec.signature = signature;
  patch_spec.offset = offset;
  patch_spec.patch = replace_data;
  patch_spec.required = true;

  p1ll::engine::recipe recipe;
  recipe.name = "p1llx.patch";
  recipe.patches.push_back(patch_spec);

  auto plan = session.plan(recipe);
  if (!plan.ok()) {
    log.err("failed to build patch plan", redlog::field("error", plan.status.message));
    std::cerr << "error: " << plan.status.message << std::endl;
    return 1;
  }

  auto report = session.apply(plan.value);
  if (!report.ok()) {
    log.err("failed to apply patch plan", redlog::field("error", report.status.message));
    std::cerr << "error: " << report.status.message << std::endl;
    return 1;
  }
  if (!report.value.success) {
    log.err("patch plan failed", redlog::field("applied", report.value.applied));
    std::cerr << "error: patch plan failed" << std::endl;
    return 1;
  }

  if (!p1ll::utils::write_file(output_file, *file_data)) {
    log.err("failed to write output file", redlog::field("path", output_file));
    std::cerr << "error: failed to write output file: " << output_file << std::endl;
    return 1;
  }

  std::cout << "patch applied successfully" << std::endl;
  if (plan.value.size() == 1) {
    std::cout << "patched " << p1ll::utils::format_address(plan.value.front().address) << std::endl;
  } else {
    std::cout << "patched " << plan.value.size() << " locations" << std::endl;
  }

  return 0;
}

} // namespace p1llx::commands
