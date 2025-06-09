#include <stdio.h>
#include <signal.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define getpid _getpid
#define usleep(x) Sleep((x) / 1000)
volatile BOOL running = TRUE;
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("long_running_target: received signal, shutting down...\n");
        running = FALSE;
        return TRUE;
    }
    return FALSE;
}
#else
#include <unistd.h>
volatile int running = 1;
void signal_handler(int sig) {
    printf("long_running_target: received signal %d, shutting down...\n", sig);
    running = 0;
}
#endif

void do_work() {
    // simulate some computational work
    volatile int sum = 0;
    for (int i = 0; i < 1000000; i++) {
        sum += i;
    }
}

int main() {
#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
#endif
    
    printf("long_running_target: started (PID: %d)\n", getpid());
    printf("long_running_target: performing continuous work...\n");
    
    int counter = 0;
    time_t start_time = time(NULL);
    
    while (running) {
        do_work();
        
        counter++;
        time_t current_time = time(NULL);
        
        if (counter % 100 == 0) {
            printf("long_running_target: completed %d work cycles (running for %ld seconds)\n", 
                   counter, current_time - start_time);
        }
        
        // exit after 10 seconds for testing
        if (current_time - start_time >= 10) {
            printf("long_running_target: 10 second limit reached, exiting\n");
            break;
        }
        
        // small delay to make it easier to inject
        usleep(10000); // 10ms
    }
    
    printf("long_running_target: completed %d total work cycles\n", counter);
    printf("long_running_target: exiting\n");
    return 0;
}