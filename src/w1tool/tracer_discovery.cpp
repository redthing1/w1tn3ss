#include "tracer_discovery.hpp"

#include <algorithm>
#include <filesystem>

#include <redlog.hpp>

#include <w1common/platform_utils.hpp>

namespace w1tool::tracer_discovery {

std::string extract_tracer_name(const std::string& library_filename) {
  auto log = redlog::get_logger("w1tool.tracer_discovery");

  // expect format: {tracer_name}_qbdipreload.{ext}
  const std::string suffix = "_qbdipreload";

  // find the suffix in the filename
  size_t suffix_pos = library_filename.find(suffix);
  if (suffix_pos == std::string::npos) {
    log.debug(
        "library filename does not match expected pattern", redlog::field("filename", library_filename),
        redlog::field("expected_pattern", "*_qbdipreload.*")
    );
    return "";
  }

  // extract tracer name (everything before the suffix)
  std::string tracer_name = library_filename.substr(0, suffix_pos);

  if (tracer_name.empty()) {
    log.debug("extracted empty tracer name", redlog::field("filename", library_filename));
    return "";
  }

  log.debug(
      "extracted tracer name", redlog::field("filename", library_filename), redlog::field("tracer_name", tracer_name)
  );

  return tracer_name;
}

std::map<std::string, std::string> find_tracer_libraries(const std::string& executable_path) {
  auto log = redlog::get_logger("w1tool.tracer_discovery");
  std::map<std::string, std::string> tracers;

  // convert executable path to absolute path
  std::filesystem::path exec_path;
  try {
    exec_path = std::filesystem::canonical(executable_path);
  } catch (const std::exception& e) {
    log.debug(
        "failed to canonicalize executable path, using as-is", redlog::field("path", executable_path),
        redlog::field("error", e.what())
    );
    exec_path = std::filesystem::path(executable_path);
  }

  std::filesystem::path exec_dir = exec_path.parent_path();
  std::string lib_ext = w1::common::platform_utils::get_library_extension();

  log.debug(
      "searching for tracer libraries", redlog::field("exec_dir", exec_dir.string()), redlog::field("lib_ext", lib_ext)
  );

  // search paths relative to executable directory
  std::vector<std::filesystem::path> search_dirs = {
      exec_dir,                // same directory as executable
      exec_dir / "lib",        // lib/ subdirectory
      exec_dir / ".." / "lib", // ../lib/ (for installed layouts)
      exec_dir / "..",         // parent directory
  };

  for (const auto& search_dir : search_dirs) {
    if (!std::filesystem::exists(search_dir) || !std::filesystem::is_directory(search_dir)) {
      continue;
    }

    log.debug("scanning directory", redlog::field("dir", search_dir.string()));

    try {
      for (const auto& entry : std::filesystem::directory_iterator(search_dir)) {
        if (!entry.is_regular_file()) {
          continue;
        }

        std::string filename = entry.path().filename().string();

        // check if it matches the pattern *_qbdipreload{lib_ext}
        if (filename.find("_qbdipreload") == std::string::npos || !filename.ends_with(lib_ext)) {
          continue;
        }

        std::string tracer_name = extract_tracer_name(filename);
        if (tracer_name.empty()) {
          continue;
        }

        // if we haven't found this tracer yet, add it
        if (tracers.count(tracer_name) == 0) {
          std::string canonical_path = std::filesystem::canonical(entry.path()).string();
          tracers[tracer_name] = canonical_path;

          log.info("found tracer library", redlog::field("tracer", tracer_name), redlog::field("path", canonical_path));
        }
      }
    } catch (const std::exception& e) {
      log.debug(
          "error scanning directory", redlog::field("dir", search_dir.string()), redlog::field("error", e.what())
      );
    }
  }

  log.info("tracer discovery complete", redlog::field("tracers_found", tracers.size()));

  return tracers;
}

std::string find_tracer_library(const std::string& executable_path, const std::string& tracer_name) {
  const auto tracers = find_tracer_libraries(executable_path);
  const auto it = tracers.find(tracer_name);
  return it != tracers.end() ? it->second : "";
}

std::vector<tracer_info> list_available_tracers(const std::string& executable_path) {
  const auto tracers = find_tracer_libraries(executable_path);
  std::vector<tracer_info> result;
  result.reserve(tracers.size());

  for (const auto& [name, path] : tracers) {
    result.push_back({name, path});
  }

  // sort by tracer name for consistent output
  std::sort(result.begin(), result.end(), [](const tracer_info& a, const tracer_info& b) -> bool {
    return a.name < b.name;
  });

  return result;
}

} // namespace w1tool::tracer_discovery