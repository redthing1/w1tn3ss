#include "insert_library.hpp"
#include "w1tn3ss/import_insertion/import_insertion.hpp"
#include <redlog.hpp>

namespace w1tool::commands {

int insert_library(
    args::Positional<std::string>& dylib_path, args::Positional<std::string>& binary_path,
    args::Positional<std::string>& output_path, args::Flag& inplace, args::Flag& weak, args::Flag& overwrite,
    args::Flag& strip_codesig, args::Flag& all_yes, args::Flag& show_platforms
) {
  auto log = redlog::get_logger("w1tool.insert_library");

  // handle --show-platforms flag
  if (show_platforms) {
    std::cout << w1::import_insertion::get_platform_support_info() << std::endl;
    return 0;
  }

  // validate required arguments
  if (!dylib_path) {
    log.err("dylib_path is required");
    return 1;
  }

  if (!binary_path) {
    log.err("binary_path is required");
    return 1;
  }

  // validate inplace and output_path combination
  if (args::get(inplace) && output_path) {
    log.err("--inplace cannot be used with output_path");
    return 1;
  }

  std::string dylib_path_str = args::get(dylib_path);
  std::string binary_path_str = args::get(binary_path);

  // create configuration
  w1::import_insertion::config cfg;
  cfg.library_path = dylib_path_str;
  cfg.target_binary = binary_path_str;
  cfg.in_place = args::get(inplace);
  cfg.weak_import = args::get(weak);
  cfg.overwrite_existing = args::get(overwrite);
  cfg.strip_code_signature = args::get(strip_codesig);
  cfg.assume_yes = args::get(all_yes);

  if (output_path) {
    cfg.output_path = args::get(output_path);
  }

  log.info(
      "insert library starting", redlog::field("dylib_path", cfg.library_path),
      redlog::field("binary_path", cfg.target_binary), redlog::field("in_place", cfg.in_place),
      redlog::field("weak_import", cfg.weak_import), redlog::field("overwrite_existing", cfg.overwrite_existing),
      redlog::field("strip_code_signature", cfg.strip_code_signature), redlog::field("assume_yes", cfg.assume_yes)
  );

  if (output_path) {
    log.info("output path specified", redlog::field("output_path", args::get(output_path)));
  }

  // perform library import insertion
  auto result = w1::import_insertion::insert_library_import(cfg);

  // handle result
  if (result.success()) {
    log.info("library import insertion completed successfully");
    return 0;
  } else {
    log.err(
        "library import insertion failed",
        redlog::field("error_code", w1::import_insertion::error_code_to_string(result.code)),
        redlog::field("error_message", result.error_message)
    );

    if (result.system_error_code.has_value()) {
      log.err("system error code", redlog::field("code", *result.system_error_code));
    }

    return 1;
  }
}

} // namespace w1tool::commands