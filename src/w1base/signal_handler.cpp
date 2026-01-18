#include "w1base/signal_handler.hpp"
#include "w1base/stderr_write.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <vector>

#ifdef _WIN32
#include <w1base/windows_clean.hpp>
#else
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <redlog.hpp>

namespace w1::tn3ss::signal_handler {

namespace {

struct handler_entry {
  signal_callback callback;
  std::string context;
};

struct cleanup_entry {
  cleanup_callback callback;
  int priority;
  std::string context;
};

// global state
std::mutex g_mutex;
std::vector<handler_entry> g_handlers;
std::vector<cleanup_entry> g_cleanups;
std::vector<int> g_forwarding_pids;
config g_config;
std::atomic<bool> g_initialized{false};
redlog::logger g_log("w1.signal_handler");

void perform_cleanup() {
  // copy cleanup handlers and sort by priority (highest first)
  std::vector<cleanup_entry> cleanups;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    cleanups = g_cleanups;
  }

  std::sort(cleanups.begin(), cleanups.end(), [](const cleanup_entry& a, const cleanup_entry& b) {
    return a.priority > b.priority;
  });

  // execute cleanup handlers
  for (const auto& cleanup : cleanups) {
    try {
      cleanup.callback();
    } catch (...) {
      // can't safely log in signal context
    }
  }
}

#ifdef _WIN32
BOOL WINAPI console_handler(DWORD ctrl_type) {
  if (ctrl_type != CTRL_C_EVENT) {
    return FALSE;
  }

  if (g_config.log_signals) {
    const char* msg = "received ctrl+c signal\n";
    w1::util::stderr_write(msg);
  }

  // forward to child processes
  std::vector<int> pids;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    pids = g_forwarding_pids;
  }

  for (int pid : pids) {
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (process) {
      TerminateProcess(process, 1);
      CloseHandle(process);
    }
  }

  // call registered handlers
  std::vector<handler_entry> handlers;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    handlers = g_handlers;
  }

  for (const auto& handler : handlers) {
    try {
      handler.callback(handler.context);
    } catch (...) {
      // can't safely log
    }
  }

  perform_cleanup();
  ExitProcess(1);
  return TRUE;
}

#else
void unix_handler(int signum, siginfo_t* info, void* context) {
  if (signum != SIGINT) {
    return;
  }

  if (g_config.log_signals) {
    const char* msg = "received sigint signal\n";
    w1::util::stderr_write(msg);
  }

  // forward to child processes
  std::vector<int> pids;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    pids = g_forwarding_pids;
  }

  for (int pid : pids) {
    kill(pid, SIGINT);
  }

  // call registered handlers
  std::vector<handler_entry> handlers;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    handlers = g_handlers;
  }

  for (const auto& handler : handlers) {
    try {
      handler.callback(handler.context);
    } catch (...) {
      // can't safely log
    }
  }

  perform_cleanup();

  // restore default handler and re-raise to actually terminate
  signal(SIGINT, SIG_DFL);
  raise(SIGINT);
}
#endif

} // anonymous namespace

bool initialize(const config& cfg) {
  if (g_initialized.exchange(true)) {
    return true; // already initialized
  }

  {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_config = cfg;
    g_log = redlog::logger("w1.signal_handler." + cfg.context_name);
  }

  g_log.info("initializing signal handler system", redlog::field("context", cfg.context_name));

#ifdef _WIN32
  if (!SetConsoleCtrlHandler(console_handler, TRUE)) {
    g_log.err("failed to install console control handler");
    g_initialized = false;
    return false;
  }
#else
  struct sigaction sa;
  sa.sa_sigaction = unix_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO | SA_RESTART;

  if (sigaction(SIGINT, &sa, nullptr) != 0) {
    g_log.err("failed to install signal handler", redlog::field("error", strerror(errno)));
    g_initialized = false;
    return false;
  }
#endif

  return true;
}

bool register_handler(signal_callback callback, const std::string& context) {
  if (!g_initialized) {
    return false;
  }

  std::lock_guard<std::mutex> lock(g_mutex);
  g_handlers.push_back({callback, context});

  g_log.dbg("registered signal handler", redlog::field("context", context));
  return true;
}

bool register_cleanup(cleanup_callback callback, int priority, const std::string& context) {
  if (!g_initialized) {
    return false;
  }

  std::lock_guard<std::mutex> lock(g_mutex);
  g_cleanups.push_back({callback, priority, context});

  g_log.dbg("registered cleanup handler", redlog::field("context", context), redlog::field("priority", priority));
  return true;
}

bool setup_forwarding(int child_pid) {
  if (!g_initialized) {
    return false;
  }

  std::lock_guard<std::mutex> lock(g_mutex);

  auto it = std::find(g_forwarding_pids.begin(), g_forwarding_pids.end(), child_pid);
  if (it == g_forwarding_pids.end()) {
    g_forwarding_pids.push_back(child_pid);
    g_log.dbg("setup signal forwarding", redlog::field("child_pid", child_pid));
  }

  return true;
}

void remove_forwarding(int child_pid) {
  std::lock_guard<std::mutex> lock(g_mutex);

  auto it = std::find(g_forwarding_pids.begin(), g_forwarding_pids.end(), child_pid);
  if (it != g_forwarding_pids.end()) {
    g_forwarding_pids.erase(it);
    g_log.dbg("removed signal forwarding", redlog::field("child_pid", child_pid));
  }
}

void shutdown() {
  if (!g_initialized.exchange(false)) {
    return; // not initialized
  }

  g_log.info("shutting down signal handler system");

  {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_handlers.clear();
    g_cleanups.clear();
    g_forwarding_pids.clear();
  }

#ifdef _WIN32
  SetConsoleCtrlHandler(console_handler, FALSE);
#else
  signal(SIGINT, SIG_DFL);
#endif
}

// raii guard implementation
guard::guard(const config& cfg) : initialized_(initialize(cfg)) {}

guard::~guard() {
  if (initialized_) {
    shutdown();
  }
}

bool guard::is_initialized() const { return initialized_; }

} // namespace w1::tn3ss::signal_handler
