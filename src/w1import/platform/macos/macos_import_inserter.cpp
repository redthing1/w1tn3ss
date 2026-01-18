#include "macos_import_inserter.hpp"
#include "../../backend/macos/macho_processor.hpp"
#include <filesystem>
#include <redlog.hpp>

// macOS-specific includes
#include <copyfile.h>

namespace fs = std::filesystem;

namespace w1::import_insertion::macos {

result insert_library_import(const config& cfg) {
  auto log = redlog::get_logger("w1.import_insertion.macos");

  log.inf(
      "starting macos library import insertion", redlog::field("library_path", cfg.library_path),
      redlog::field("target_binary", cfg.target_binary), redlog::field("in_place", cfg.in_place),
      redlog::field("weak", cfg.weak_import)
  );

  // check if dylib exists (unless it's a special path like @rpath)
  if (cfg.library_path[0] != '@' && !fs::exists(cfg.library_path)) {
    log.warn("dylib path does not exist", redlog::field("path", cfg.library_path));
    if (!cfg.assume_yes) {
      return result{
          .code = error_code::library_path_invalid, .error_message = "library path does not exist: " + cfg.library_path
      };
    } else {
      log.info("continuing anyway (assume_yes=true)");
    }
  }

  // check if binary exists
  if (!fs::exists(cfg.target_binary)) {
    log.error("binary path does not exist", redlog::field("path", cfg.target_binary));
    return result{.code = error_code::file_not_found, .error_message = "target binary not found: " + cfg.target_binary};
  }

  // determine output path
  std::string final_binary_path;
  if (cfg.in_place) {
    final_binary_path = cfg.target_binary;
    log.trc("using in-place modification");
  } else if (cfg.output_path) {
    final_binary_path = *cfg.output_path;
    log.trc("using specified output path", redlog::field("output_path", final_binary_path));
  } else {
    final_binary_path = cfg.target_binary + "_patched";
    log.trc("using default output path", redlog::field("output_path", final_binary_path));
  }

  // copy file if not in-place
  if (!cfg.in_place) {
    if (fs::exists(final_binary_path) && !cfg.overwrite_existing) {
      if (!cfg.assume_yes) {
        return result{
            .code = error_code::output_already_exists,
            .error_message = "output file already exists: " + final_binary_path + " (use overwrite_existing=true)"
        };
      } else {
        log.info("overwriting existing output file (assume_yes=true)");
      }
    }

    // use copyfile for proper macOS file copying
    if (copyfile(cfg.target_binary.c_str(), final_binary_path.c_str(), nullptr, COPYFILE_DATA | COPYFILE_UNLINK) != 0) {
      log.error(
          "failed to copy file", redlog::field("source", cfg.target_binary),
          redlog::field("destination", final_binary_path)
      );
      return result{
          .code = error_code::system_error,
          .error_message = "failed to copy binary to output path",
          .system_error_code = errno
      };
    }
    log.info(
        "copied file", redlog::field("source", cfg.target_binary), redlog::field("destination", final_binary_path)
    );
  }

  try {
    // process the binary
    log.trc("initializing mach-o processor", redlog::field("file", final_binary_path));
    backend::macos::MachOProcessor processor(
        final_binary_path, cfg.weak_import, cfg.strip_code_signature, !cfg.assume_yes
    );

    log.trc("beginning dylib insertion process");
    if (processor.insert_dylib_load_command(cfg.library_path)) {
      std::string lc_name = cfg.weak_import ? "LC_LOAD_WEAK_DYLIB" : "LC_LOAD_DYLIB";
      log.inf(
          "successfully added dylib load command", redlog::field("dylib", cfg.library_path),
          redlog::field("binary", final_binary_path), redlog::field("load_command", lc_name)
      );
      return result{.code = error_code::success, .error_message = "library import inserted successfully"};
    } else {
      log.error("failed to insert dylib load command");
      if (!cfg.in_place) {
        log.dbg("cleaning up failed output file", redlog::field("file", final_binary_path));
        fs::remove(final_binary_path);
      }
      return result{
          .code = error_code::unknown_error, .error_message = "mach-o processor failed to insert library import"
      };
    }
  } catch (const std::exception& e) {
    log.error("error processing binary", redlog::field("error", e.what()));
    if (!cfg.in_place) {
      fs::remove(final_binary_path);
    }
    return result{
        .code = error_code::system_error, .error_message = std::string("binary processing error: ") + e.what()
    };
  }
}

bool check_import_capabilities() {
  return true; // macOS is fully supported
}

} // namespace w1::import_insertion::macos