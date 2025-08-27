/*
 * Linux-specific test library for injection testing
 * Tests Linux-specific hooking and injection functionality
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>

static int initialized = 0;
static FILE* log_file = NULL;

// Function pointers for original functions
static int (*orig_open)(const char* pathname, int flags, ...) = NULL;
static int (*orig_close)(int fd) = NULL;
static void* (*orig_malloc)(size_t size) = NULL;
static void (*orig_free)(void* ptr) = NULL;
static pid_t (*orig_getpid)(void) = NULL;

void log_message(const char* format, ...) {
  if (!log_file) {
    return;
  }

  va_list args;
  va_start(args, format);

  time_t now = time(NULL);
  struct tm* tm_info = localtime(&now);

  fprintf(log_file, "[%02d:%02d:%02d] ", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
  vfprintf(log_file, format, args);
  fprintf(log_file, "\n");
  fflush(log_file);

  va_end(args);
}

void initialize_library() {
  if (initialized) {
    return;
  }

  // Open log file
  log_file = fopen("/tmp/linux_test_lib.log", "a");
  if (!log_file) {
    // Fallback to syslog
    openlog("linux_test_lib", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "linux_test_lib: initialized (no log file)");
  } else {
    log_message("linux_test_lib: initialized (PID: %d)", getpid());
  }

  // Get original function pointers
  orig_open = dlsym(RTLD_NEXT, "open");
  orig_close = dlsym(RTLD_NEXT, "close");
  orig_malloc = dlsym(RTLD_NEXT, "malloc");
  orig_free = dlsym(RTLD_NEXT, "free");
  orig_getpid = dlsym(RTLD_NEXT, "getpid");

  initialized = 1;

  if (log_file) {
    log_message("linux_test_lib: function pointers resolved");
  }
}

void cleanup_library() {
  if (log_file) {
    log_message("linux_test_lib: cleaning up");
    fclose(log_file);
    log_file = NULL;
  }
  closelog();
}

// Constructor/destructor
__attribute__((constructor)) void library_init() { initialize_library(); }

__attribute__((destructor)) void library_cleanup() { cleanup_library(); }

// Hooked functions
int open(const char* pathname, int flags, ...) {
  initialize_library();

  if (!orig_open) {
    errno = ENOSYS;
    return -1;
  }

  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list args;
    va_start(args, flags);
    mode = va_arg(args, mode_t);
    va_end(args);
  }

  int result = orig_open(pathname, flags, mode);

  log_message("open(%s, %d) = %d", pathname, flags, result);

  return result;
}

int close(int fd) {
  initialize_library();

  if (!orig_close) {
    errno = ENOSYS;
    return -1;
  }

  int result = orig_close(fd);

  log_message("close(%d) = %d", fd, result);

  return result;
}

void* malloc(size_t size) {
  initialize_library();

  if (!orig_malloc) {
    return NULL;
  }

  void* result = orig_malloc(size);

  // Be careful with logging in malloc to avoid recursion
  if (log_file && size > 1024) { // Only log large allocations
    log_message("malloc(%zu) = %p", size, result);
  }

  return result;
}

void free(void* ptr) {
  initialize_library();

  if (!orig_free) {
    return;
  }

  if (log_file && ptr) {
    log_message("free(%p)", ptr);
  }

  orig_free(ptr);
}

pid_t getpid(void) {
  initialize_library();

  if (!orig_getpid) {
    return syscall(SYS_getpid);
  }

  pid_t result = orig_getpid();

  // Log occasionally to avoid spam
  static int call_count = 0;
  if (++call_count % 10 == 1) {
    log_message("getpid() = %d (call #%d)", result, call_count);
  }

  return result;
}

// Test function that can be called from injected code
void linux_test_function() {
  initialize_library();
  log_message("linux_test_function called");
}

// Export symbol for testing
int linux_test_lib_version() { return 1; }