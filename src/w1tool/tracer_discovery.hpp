#pragma once

#include <map>
#include <string>
#include <vector>

namespace w1tool::tracer_discovery {

/**
 * @brief Discovery result containing tracer name and library path
 */
struct tracer_info {
  std::string name;
  std::string library_path;
};

/**
 * @brief Find all available tracer libraries relative to the executable
 * @param executable_path path to the current executable
 * @return map of tracer names to their library paths
 */
std::map<std::string, std::string> find_tracer_libraries(const std::string& executable_path);

/**
 * @brief Find a specific tracer library by name
 * @param executable_path path to the current executable
 * @param tracer_name name of the tracer to find (e.g., "w1cov", "w1mem")
 * @return path to the library if found, empty string otherwise
 */
std::string find_tracer_library(const std::string& executable_path, const std::string& tracer_name);

/**
 * @brief Extract tracer name from library filename
 * @param library_filename filename of the library (e.g., "w1cov_qbdipreload.so")
 * @return tracer name (e.g., "w1cov") or empty string if invalid format
 */
std::string extract_tracer_name(const std::string& library_filename);

/**
 * @brief Get list of all available tracers
 * @param executable_path path to the current executable
 * @return vector of tracer information
 */
std::vector<tracer_info> list_available_tracers(const std::string& executable_path);

} // namespace w1tool::tracer_discovery