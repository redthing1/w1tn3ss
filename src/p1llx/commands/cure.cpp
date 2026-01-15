#include "cure.hpp"
#include <p1ll/p1ll.hpp>
#include <p1ll/scripting/script_engine_factory.hpp>
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

    // create buffer session
    p1ll::engine::session session = p1ll::engine::session::for_buffer(buffer_data);
    if (!platform_override.empty()) {
      auto parsed = p1ll::engine::platform::parse_platform(platform_override);
      if (!parsed.ok()) {
        log.err("invalid platform override", redlog::field("platform", platform_override));
        std::cerr << "invalid platform override '" << platform_override << "'" << std::endl;
        return 1;
      }
      log.inf("using platform override", redlog::field("platform", parsed.value.to_string()));
      session = p1ll::engine::session::for_buffer(buffer_data, parsed.value);
    }

    auto script_engine = p1ll::scripting::ScriptEngineFactory::create();
    if (!script_engine) {
      std::cerr << "failed to create script engine" << std::endl;
      return 1;
    }
    auto result = script_engine->execute_script(session, script_content);
    if (result.ok() && result.value.success) {
      // write modified buffer to output file
      std::ofstream output_stream(output_file, std::ios::binary);
      if (!output_stream) {
        std::cerr << "failed to create output file: " << output_file << std::endl;
        return 1;
      }

      output_stream.write(reinterpret_cast<const char*>(buffer_data.data()), buffer_data.size());

      log.inf(
          "cure completed successfully", redlog::field("patches_applied", result.value.applied),
          redlog::field("patches_failed", result.value.failed)
      );

      return 0;
    } else {
      size_t error_count = result.value.diagnostics.size();
      log.err("cure failed", redlog::field("errors", error_count));

      std::cerr << "cure failed with " << error_count << " errors:" << std::endl;
      for (const auto& error : result.value.diagnostics) {
        std::cerr << "  error: " << error.message << std::endl;
        log.err("cure error detail", redlog::field("message", error.message));
      }
      if (!result.ok() && !result.status.message.empty()) {
        std::cerr << "  error: " << result.status.message << std::endl;
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
