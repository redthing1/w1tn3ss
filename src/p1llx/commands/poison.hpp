#pragma once

#include <string>
#include <vector>

namespace p1llx::commands {

/**
 * @brief Inject p01s0n library into target process for dynamic patching (spawn method)
 *
 * Uses preload injection to load p01s0n.so/dylib/dll into the target process.
 * The POISON_CURE environment variable specifies which cure script to apply.
 *
 * @param script_path Path to lua cure script (sets POISON_CURE env var)
 * @param binary_path Path to target binary to launch and inject
 * @param binary_args Arguments to pass to target binary
 * @param suspended Whether to start target in suspended mode
 * @param executable_path Path to p1llx executable for library discovery
 * @param verbosity_level Verbosity level to pass to p01s0n (0-3)
 * @return 0 for success, 1 for failure
 */
int poison_spawn(
    const std::string& script_path, const std::string& binary_path, const std::vector<std::string>& binary_args = {},
    bool suspended = false, const std::string& executable_path = "", int verbosity_level = 0
);

/**
 * @brief Inject p01s0n library into existing process by PID (runtime method)
 *
 * Uses runtime injection to load p01s0n.so/dylib/dll into an existing process.
 * The POISON_CURE environment variable specifies which cure script to apply.
 *
 * @param script_path Path to lua cure script (sets POISON_CURE env var)
 * @param target_pid Process ID of target process
 * @param executable_path Path to p1llx executable for library discovery
 * @param verbosity_level Verbosity level to pass to p01s0n (0-3)
 * @return 0 for success, 1 for failure
 */
int poison_pid(
    const std::string& script_path, int target_pid, const std::string& executable_path = "", int verbosity_level = 0
);

/**
 * @brief Inject p01s0n library into existing process by name (runtime method)
 *
 * Uses runtime injection to load p01s0n.so/dylib/dll into an existing process.
 * The POISON_CURE environment variable specifies which cure script to apply.
 *
 * @param script_path Path to lua cure script (sets POISON_CURE env var)
 * @param process_name Name of target process
 * @param executable_path Path to p1llx executable for library discovery
 * @param verbosity_level Verbosity level to pass to p01s0n (0-3)
 * @return 0 for success, 1 for failure
 */
int poison_process_name(
    const std::string& script_path, const std::string& process_name, const std::string& executable_path = "",
    int verbosity_level = 0
);

} // namespace p1llx::commands