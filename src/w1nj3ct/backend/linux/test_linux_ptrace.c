#ifdef __linux__
#include "linux_ptrace.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>

// simple test program to validate the Linux ptrace interface
int main() {
    printf("Linux ptrace backend test\n");
    
    // create a child process to test ptrace operations
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // child process - just loop indefinitely
        while (1) {
            sleep(1);
        }
        return 0;
    } else if (child_pid > 0) {
        // parent process - test ptrace operations
        printf("Testing ptrace attach on PID %d\n", child_pid);
        
        // test attach
        int result = linux_ptrace_attach(child_pid);
        if (result == LINUX_PTRACE_SUCCESS) {
            printf("✓ Attach successful\n");
            
            // test register operations
            struct linux_user_regs regs;
            result = linux_ptrace_get_registers(child_pid, &regs);
            if (result == LINUX_PTRACE_SUCCESS) {
                printf("✓ Get registers successful\n");
#if defined(__x86_64__)
                printf("  RIP: 0x%llx\n", regs.regs.rip);
                printf("  RSP: 0x%llx\n", regs.regs.rsp);
#elif defined(__aarch64__)
                printf("  PC: 0x%llx\n", regs.regs.pc);
                printf("  SP: 0x%llx\n", regs.regs.sp);
#endif
            } else {
                printf("✗ Get registers failed: %s\n", linux_ptrace_strerror(result));
            }
            
            // test memory read
            char buffer[64];
            result = linux_ptrace_read_memory(child_pid, (void*)0x400000, buffer, sizeof(buffer));
            if (result == LINUX_PTRACE_SUCCESS) {
                printf("✓ Memory read successful\n");
            } else {
                printf("⚠ Memory read failed (expected): %s\n", linux_ptrace_strerror(result));
            }
            
            // test detach
            result = linux_ptrace_detach(child_pid);
            if (result == LINUX_PTRACE_SUCCESS) {
                printf("✓ Detach successful\n");
            } else {
                printf("✗ Detach failed: %s\n", linux_ptrace_strerror(result));
            }
        } else {
            printf("✗ Attach failed: %s\n", linux_ptrace_strerror(result));
        }
        
        // clean up child process
        kill(child_pid, SIGTERM);
        waitpid(child_pid, NULL, 0);
        
        printf("Test completed\n");
    } else {
        perror("fork failed");
        return 1;
    }
    
    return 0;
}
#else
#include <stdio.h>
int main() {
    printf("Linux ptrace test requires Linux platform\n");
    return 0;
}
#endif