/*
 * Linux daemon-like target for testing injection into backgrounded processes
 * Tests injection into processes that have detached from terminal
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

volatile int running = 1;
const char* pidfile_path = "/tmp/linux_daemon.pid";

void signal_handler(int sig) {
  syslog(LOG_INFO, "linux_daemon: received signal %d", sig);
  running = 0;
}

void cleanup() {
  unlink(pidfile_path);
  closelog();
}

int create_pidfile() {
  FILE* f = fopen(pidfile_path, "w");
  if (!f) {
    return -1;
  }
  fprintf(f, "%d\n", getpid());
  fclose(f);
  return 0;
}

void daemonize() {
  pid_t pid = fork();

  if (pid < 0) {
    exit(EXIT_FAILURE);
  }

  if (pid > 0) {
    // Parent process exits
    exit(EXIT_SUCCESS);
  }

  // Child continues as daemon
  if (setsid() < 0) {
    exit(EXIT_FAILURE);
  }

  // Change working directory to root
  if (chdir("/") < 0) {
    exit(EXIT_FAILURE);
  }

  // Close file descriptors
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  // Redirect standard file descriptors to /dev/null
  open("/dev/null", O_RDONLY); // stdin
  open("/dev/null", O_WRONLY); // stdout
  open("/dev/null", O_WRONLY); // stderr
}

void daemon_work() {
  // Simulate daemon work
  int work_counter = 0;

  while (running) {
    syslog(LOG_INFO, "linux_daemon: work iteration %d", work_counter++);

    // Simulate some work
    void* ptr = malloc(1024);
    if (ptr) {
      memset(ptr, work_counter & 0xFF, 1024);
      free(ptr);
    }

    // Check if we should exit
    if (work_counter >= 15) { // Run for limited time in testing
      syslog(LOG_INFO, "linux_daemon: work limit reached, exiting");
      break;
    }

    sleep(2);
  }
}

int main(int argc, char* argv[]) {
  int foreground = 0;

  // Simple argument parsing
  if (argc > 1 && strcmp(argv[1], "--foreground") == 0) {
    foreground = 1;
  }

  // Open syslog
  openlog("linux_daemon", LOG_PID | LOG_CONS, LOG_DAEMON);

  if (!foreground) {
    printf("linux_daemon: daemonizing (PID: %d)\n", getpid());
    daemonize();
  } else {
    printf("linux_daemon: running in foreground (PID: %d)\n", getpid());
  }

  syslog(LOG_INFO, "linux_daemon: started (PID: %d)", getpid());

  // Set up signal handlers
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGHUP, signal_handler);

  // Create PID file
  if (create_pidfile() < 0) {
    syslog(LOG_ERR, "linux_daemon: failed to create PID file");
  }

  // Set up cleanup
  atexit(cleanup);

  // Log injection indicators
  if (getenv("LD_PRELOAD")) {
    syslog(LOG_INFO, "linux_daemon: LD_PRELOAD detected: %s", getenv("LD_PRELOAD"));
  }

  // Do daemon work
  daemon_work();

  syslog(LOG_INFO, "linux_daemon: exiting");
  return 0;
}