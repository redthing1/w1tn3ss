#include "windows_import_inserter.hpp"
#include <filesystem>
#include <redlog.hpp>

#ifdef WITNESS_LIEF_ENABLED
#include <LIEF/PE.hpp>
#endif

namespace fs = std::filesystem;

namespace w1::import_insertion::windows {

result insert_library_import(const config& cfg) {
  auto log = redlog::get_logger("w1.import_insertion.windows");

#ifndef WITNESS_LIEF_ENABLED
  log.error("windows library import insertion requires LIEF support");
  return result{
      .code = error_code::platform_not_supported,
      .error_message = "windows library import insertion requires LIEF library support (build with -DWITNESS_LIEF=ON)"
  };
#else

  log.inf(
      "starting windows pe library import insertion", redlog::field("library_path", cfg.library_path),
      redlog::field("target_binary", cfg.target_binary), redlog::field("in_place", cfg.in_place)
  );

  // validate binary exists
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

  // check if output already exists
  if (final_binary_path != cfg.target_binary && fs::exists(final_binary_path) && !cfg.overwrite_existing) {
    if (!cfg.assume_yes) {
      return result{
          .code = error_code::output_already_exists,
          .error_message = "output file already exists: " + final_binary_path + " (use overwrite_existing=true)"
      };
    } else {
      log.info("overwriting existing output file (assume_yes=true)");
    }
  }

  try {
    // parse pe binary
    log.trc("parsing pe binary", redlog::field("file", cfg.target_binary));
    auto pe = LIEF::PE::Parser::parse(cfg.target_binary);
    if (!pe) {
      log.error("failed to parse pe binary", redlog::field("file", cfg.target_binary));
      return result{
          .code = error_code::invalid_binary_format,
          .error_message = "failed to parse PE binary - invalid format or corrupted file"
      };
    }

    // validate architecture compatibility if needed
    log.dbg(
        "pe binary details", redlog::field("machine_type", static_cast<int>(pe->header().machine())),
        redlog::field("is_32bit", pe->type() == LIEF::PE::PE_TYPE::PE32),
        redlog::field("is_64bit", pe->type() == LIEF::PE::PE_TYPE::PE32_PLUS)
    );

    // check for existing import
    bool already_imported = false;
    for (const auto& import : pe->imports()) {
      if (import.name() == cfg.library_path) {
        already_imported = true;
        log.trc("duplicate dll detected", redlog::field("dll", cfg.library_path));
        if (!cfg.assume_yes) {
          return result{
              .code = error_code::duplicate_library,
              .error_message = "binary already imports " + cfg.library_path + " (use assume_yes=true to continue)"
          };
        } else {
          log.info("continuing with duplicate dll import (assume_yes=true)");
        }
        break;
      }
    }

    // add library import
    if (!already_imported) {
      log.trc("adding dll import", redlog::field("dll", cfg.library_path));
      pe->add_library(cfg.library_path);

      log.dbg("dll import added successfully", redlog::field("dll", cfg.library_path));
    }

    // write modified binary
    log.trc("writing modified pe binary", redlog::field("output", final_binary_path));
    LIEF::PE::Builder builder(*pe);
    builder.write(final_binary_path);

    log.inf(
        "successfully added dll import", redlog::field("dll", cfg.library_path),
        redlog::field("binary", final_binary_path)
    );

    return result{.code = error_code::success, .error_message = "library import inserted successfully"};

  } catch (const LIEF::exception& e) {
    log.error("lief error processing pe binary", redlog::field("error", e.what()));
    return result{
        .code = error_code::invalid_binary_format, .error_message = std::string("LIEF PE processing error: ") + e.what()
    };
  } catch (const std::exception& e) {
    log.error("error processing pe binary", redlog::field("error", e.what()));
    return result{
        .code = error_code::system_error, .error_message = std::string("PE binary processing error: ") + e.what()
    };
  }
#endif
}

bool check_import_capabilities() {
#ifdef WITNESS_LIEF_ENABLED
  return true; // windows pe support available via LIEF
#else
  return false; // requires LIEF library
#endif
}

} // namespace w1::import_insertion::windows