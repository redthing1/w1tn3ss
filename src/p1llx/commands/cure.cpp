#include "cure.hpp"
#include <p1ll/p1ll.hpp>
#include <p1ll/core/platform.hpp>
#include <redlog.hpp>
#include <iostream>
#include <fstream>
#include <sstream>

namespace p1llx::commands {

int cure(
    const std::string& script_path, const std::string& input_file, const std::string& output_file,
    const std::string& platform_override
) {

  auto log = redlog::get_logger("p1llx.commands.cure");

  log.inf(
      "applying cure script to file", redlog::field("script", script_path), redlog::field("input", input_file),
      redlog::field("output", output_file), redlog::field("platform", platform_override)
  );

  try {
    // read script content
    std::ifstream script_stream(script_path);
    if (!script_stream) {
      std::cerr << "failed to open script file: " << script_path << std::endl;
      return 1;
    }

    std::ostringstream script_buffer;
    script_buffer << script_stream.rdbuf();
    std::string script_content = script_buffer.str();

    log.dbg("loaded script content", redlog::field("size", script_content.size()));

    // read input file to buffer
    std::ifstream input_stream(input_file, std::ios::binary);
    if (!input_stream) {
      std::cerr << "failed to open input file: " << input_file << std::endl;
      return 1;
    }

    std::vector<uint8_t> buffer_data((std::istreambuf_iterator<char>(input_stream)), std::istreambuf_iterator<char>());

    log.dbg("loaded input file", redlog::field("size", buffer_data.size()));

    // execute static cure with buffer
    p1ll::core::cure_result result;
    if (!platform_override.empty()) {
      // parse platform override
      try {
        auto platform_key = p1ll::core::parse_platform_key(platform_override);
        log.inf("using platform override", redlog::field("platform", platform_key.to_string()));
        result = p1ll::execute_static_cure_with_platform(script_content, buffer_data, platform_key);
      } catch (const std::exception& e) {
        log.err(
            "invalid platform override", redlog::field("platform", platform_override), redlog::field("error", e.what())
        );
        std::cerr << "invalid platform override '" << platform_override << "': " << e.what() << std::endl;
        return 1;
      }
    } else {
      result = p1ll::execute_static_cure(script_content, buffer_data);
    }

    if (result.success) {
      // write modified buffer to output file
      std::ofstream output_stream(output_file, std::ios::binary);
      if (!output_stream) {
        std::cerr << "failed to create output file: " << output_file << std::endl;
        return 1;
      }

      output_stream.write(reinterpret_cast<const char*>(buffer_data.data()), buffer_data.size());

      log.inf(
          "cure completed successfully", redlog::field("patches_applied", result.patches_applied),
          redlog::field("patches_failed", result.patches_failed)
      );

      // print summary to user
      std::cout << "cure completed successfully" << std::endl;
      std::cout << "patches applied: " << result.patches_applied << std::endl;
      if (result.patches_failed > 0) {
        std::cout << "patches failed: " << result.patches_failed << std::endl;
      }

      return 0;
    } else {
      log.err("cure failed", redlog::field("errors", result.error_messages.size()));

      std::cerr << "cure failed with " << result.error_messages.size() << " errors:" << std::endl;
      for (const auto& error : result.error_messages) {
        std::cerr << "  error: " << error << std::endl;
        log.err("cure error detail", redlog::field("message", error));
      }

      return 1;
    }

  } catch (const std::exception& e) {
    log.err("cure execution failed", redlog::field("error", e.what()));
    std::cerr << "cure execution failed: " << e.what() << std::endl;
    return 1;
  }
}

} // namespace p1llx::commands