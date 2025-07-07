#pragma once

#include <functional>
#include <string>
#include <vector>

#ifdef _WIN32
#include <w1common/windows_clean.hpp>
#else
#include <signal.h>
#include <sys/types.h>
#endif

namespace w1::tn3ss::signal_handler {

/**
 * @brief callback function for signal handlers
 * @param context optional context string for debugging
 */
using signal_callback = std::function<void(const std::string& context)>;

/**
 * @brief cleanup function for graceful shutdown
 * should be signal-safe and fast
 */
using cleanup_callback = std::function<void()>;

/**
 * @brief configuration for signal handling behavior
 */
struct config {
  std::string context_name = "w1tool"; ///< context name for logging
  bool log_signals = false;            ///< log signal reception for debugging
};

/**
 * @brief initialize signal handling system
 * @param cfg configuration for signal handling behavior
 * @return true if initialization succeeded
 */
bool initialize(const config& cfg = {});

/**
 * @brief register a signal handler for SIGINT (ctrl+c)
 * @param callback function to call when signal is received
 * @param context context string for debugging/logging
 * @return true if registration succeeded
 */
bool register_handler(signal_callback callback, const std::string& context = "");

/**
 * @brief register a cleanup function to be called during graceful shutdown
 * @param callback cleanup function (should be signal-safe)
 * @param priority priority for cleanup order (higher = called first)
 * @param context context string for debugging/logging
 * @return true if registration succeeded
 */
bool register_cleanup(cleanup_callback callback, int priority = 0, const std::string& context = "");

/**
 * @brief set up signal forwarding from parent to child process
 * @param child_pid child process ID to forward signals to
 * @return true if forwarding was set up successfully
 */
bool setup_forwarding(int child_pid);

/**
 * @brief remove signal forwarding for a specific child process
 * @param child_pid child process ID to stop forwarding to
 */
void remove_forwarding(int child_pid);

/**
 * @brief cleanup and shutdown the signal handling system
 */
void shutdown();

/**
 * @brief raii helper for signal handling setup/cleanup
 */
class guard {
public:
  explicit guard(const config& cfg = {});
  ~guard();

  guard(const guard&) = delete;
  guard& operator=(const guard&) = delete;
  guard(guard&&) = delete;
  guard& operator=(guard&&) = delete;

  bool is_initialized() const;

private:
  bool initialized_;
};

} // namespace w1::tn3ss::signal_handler