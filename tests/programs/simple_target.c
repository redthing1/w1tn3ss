#include <stdio.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define getpid _getpid
#define sleep(x) Sleep((x) * 1000)
volatile BOOL running = TRUE;
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("simple_target: received signal, shutting down...\n");
        running = FALSE;
        return TRUE;
    }
    return FALSE;
}
#else
#include <unistd.h>
volatile int running = 1;
void signal_handler(int sig) {
    printf("simple_target: received signal %d, shutting down...\n", sig);
    running = 0;
}
#endif

int main() {
#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
#endif
    
    printf("simple_target: started (PID: %d)\n", getpid());
    printf("simple_target: waiting for injection or signal...\n");
    
    int counter = 0;
    while (running) {
        printf("simple_target: iteration %d\n", counter++);
        sleep(2);
        
        // exit after 10 seconds if no signal received
        if (counter >= 5) {
            printf("simple_target: timeout reached, exiting\n");
            break;
        }
    }
    
    printf("simple_target: exiting\n");
    return 0;
}