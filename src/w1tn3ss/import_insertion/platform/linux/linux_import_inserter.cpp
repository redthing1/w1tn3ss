#include "linux_import_inserter.hpp"
#include <filesystem>
#include <redlog.hpp>

#ifdef WITNESS_LIEF_ENABLED
#include <LIEF/ELF.hpp>
#endif

namespace fs = std::filesystem;

namespace w1::import_insertion::linux_impl {

result insert_library_import(const config& cfg) {
  auto log = redlog::get_logger("w1.import_insertion.linux");

#ifndef WITNESS_LIEF_ENABLED
  log.error("linux library import insertion requires LIEF support");
  return result{
      .code = error_code::platform_not_supported,
      .error_message = "linux library import insertion requires LIEF library support (build with -DWITNESS_LIEF=ON)"
  };
#else

  log.inf(
      "starting linux elf library import insertion", redlog::field("library_path", cfg.library_path),
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
    // parse elf binary
    log.trc("parsing elf binary", redlog::field("file", cfg.target_binary));
    auto elf = LIEF::ELF::Parser::parse(cfg.target_binary);
    if (!elf) {
      log.error("failed to parse elf binary", redlog::field("file", cfg.target_binary));
      return result{
          .code = error_code::invalid_binary_format,
          .error_message = "failed to parse ELF binary - invalid format or corrupted file"
      };
    }

    // validate architecture and type compatibility
    log.dbg(
        "elf binary details", redlog::field("class", static_cast<int>(elf->header().file_class())),
        redlog::field("machine", static_cast<int>(elf->header().machine_type())),
        redlog::field("type", static_cast<int>(elf->header().file_type())),
        redlog::field("is_64bit", elf->header().file_class() == LIEF::ELF::ELF_CLASS::ELFCLASS64)
    );

    // check if this is a dynamic executable/shared library
    if (elf->header().file_type() != LIEF::ELF::E_TYPE::EXEC && elf->header().file_type() != LIEF::ELF::E_TYPE::DYN) {
      log.error("unsupported elf file type", redlog::field("type", static_cast<int>(elf->header().file_type())));
      return result{
          .code = error_code::unsupported_architecture,
          .error_message = "only dynamic executables and shared libraries are supported for library import insertion"
      };
    }

    // check for existing library dependency
    bool already_imported = false;
    for (const auto& library : elf->libraries()) {
      if (library == cfg.library_path) {
        already_imported = true;
        log.trc("duplicate library detected", redlog::field("library", cfg.library_path));
        if (!cfg.assume_yes) {
          return result{
              .code = error_code::duplicate_library,
              .error_message = "binary already depends on " + cfg.library_path + " (use assume_yes=true to continue)"
          };
        } else {
          log.info("continuing with duplicate library dependency (assume_yes=true)");
        }
        break;
      }
    }

    // add library dependency
    if (!already_imported) {
      log.trc("adding library dependency", redlog::field("library", cfg.library_path));
      elf->add_library(cfg.library_path);

      log.dbg("library dependency added successfully", redlog::field("library", cfg.library_path));
    }

    // note about weak imports - elf doesn't have direct equivalent to weak dylib imports
    if (cfg.weak_import) {
      log.warn("weak imports not supported for elf format - library will be added as regular dependency");
    }

    // write modified binary
    log.trc("writing modified elf binary", redlog::field("output", final_binary_path));
    LIEF::ELF::Builder builder(*elf);
    builder.write(final_binary_path);

    log.inf(
        "successfully added library dependency", redlog::field("library", cfg.library_path),
        redlog::field("binary", final_binary_path)
    );

    return result{.code = error_code::success, .error_message = "library import inserted successfully"};

  } catch (const LIEF::exception& e) {
    log.error("lief error processing elf binary", redlog::field("error", e.what()));
    return result{
        .code = error_code::invalid_binary_format,
        .error_message = std::string("LIEF ELF processing error: ") + e.what()
    };
  } catch (const std::exception& e) {
    log.error("error processing elf binary", redlog::field("error", e.what()));
    return result{
        .code = error_code::system_error, .error_message = std::string("ELF binary processing error: ") + e.what()
    };
  }
#endif
}

bool check_import_capabilities() {
#ifdef WITNESS_LIEF_ENABLED
  return true; // linux elf support available via LIEF
#else
  return false; // requires LIEF library
#endif
}

} // namespace w1::import_insertion::linux_impl