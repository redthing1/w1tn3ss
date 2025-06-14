/*
 * Linux-specific target program for injection testing
 * Tests Linux-specific functionality like signals, ptrace detection, etc.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <string.h>
#include <time.h>

volatile int running = 1;
volatile int injection_detected = 0;

void signal_handler(int sig) {
    printf("linux_target: received signal %d (%s)\n", sig, strsignal(sig));
    if (sig == SIGTERM || sig == SIGINT) {
        running = 0;
    }
}

void check_ptrace_status() {
    // Check if we're being traced
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        if (errno == EPERM) {
            printf("linux_target: ptrace detected - we're being traced\n");
            injection_detected = 1;
        }
    } else {
        // Detach immediately if successful
        ptrace(PTRACE_DETACH, 0, NULL, NULL);
    }
}

void perform_linux_operations() {
    // Test various Linux-specific operations that might be hooked
    
    // File operations
    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer_pid = atoi(line + 10);
                if (tracer_pid != 0) {
                    printf("linux_target: TracerPid detected: %d\n", tracer_pid);
                    injection_detected = 1;
                }
                break;
            }
        }
        fclose(f);
    }
    
    // Memory operations
    void* ptr = malloc(1024);
    if (ptr) {
        memset(ptr, 0xAA, 1024);
        free(ptr);
    }
    
    // System calls
    getpid();
    getppid();
    geteuid();
    getegid();
}

void test_library_hooks() {
    // Test common functions that injection libraries might hook
    printf("linux_target: testing library function hooks\n");
    
    // Test malloc/free
    void* test_ptr = malloc(64);
    if (test_ptr) {
        free(test_ptr);
    }
    
    // Test file operations
    FILE* f = fopen("/dev/null", "w");
    if (f) {
        fwrite("test", 1, 4, f);
        fclose(f);
    }
    
    // Test network-like operations (even if they fail)
    socket(AF_INET, SOCK_STREAM, 0);
}

int main(int argc, char* argv[]) {
    printf("linux_target: Linux injection test target starting (PID: %d)\n", getpid());
    printf("linux_target: PPID: %d, UID: %d, GID: %d\n", getppid(), getuid(), getgid());
    
    // Set up signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGCHLD, signal_handler);
    signal(SIGUSR1, signal_handler);
    signal(SIGUSR2, signal_handler);
    
    // Set process name
    if (prctl(PR_SET_NAME, "linux_target", 0, 0, 0) == 0) {
        printf("linux_target: process name set\n");
    }
    
    // Check environment variables that might indicate injection
    if (getenv("LD_PRELOAD")) {
        printf("linux_target: LD_PRELOAD detected: %s\n", getenv("LD_PRELOAD"));
        injection_detected = 1;
    }
    
    int iteration = 0;
    time_t start_time = time(NULL);
    
    while (running && (time(NULL) - start_time) < 30) {  // Run for max 30 seconds
        printf("linux_target: iteration %d\n", iteration++);
        
        // Perform various operations
        perform_linux_operations();
        check_ptrace_status();
        test_library_hooks();
        
        // Print injection status
        if (injection_detected) {
            printf("linux_target: injection/debugging detected\n");
        }
        
        sleep(2);
        
        // Exit after reasonable time for testing
        if (iteration >= 10) {
            printf("linux_target: iteration limit reached\n");
            break;
        }
    }
    
    printf("linux_target: exiting after %d iterations\n", iteration);
    return injection_detected ? 42 : 0;  // Special exit code if injection detected
}