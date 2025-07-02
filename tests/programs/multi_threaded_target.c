#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define getpid _getpid
#define usleep(x) Sleep((x) / 1000)
typedef HANDLE pthread_t;
volatile BOOL running = TRUE;
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("multi_threaded_target: received signal, shutting down...\n");
        running = FALSE;
        return TRUE;
    }
    return FALSE;
}
#else
#include <unistd.h>
#include <pthread.h>
volatile int running = 1;
void signal_handler(int sig) {
    printf("multi_threaded_target: received signal %d, shutting down...\n", sig);
    running = 0;
}
#endif

typedef struct {
    int thread_id;
    const char* task_type;
    int iterations;
} thread_data_t;

#ifdef _WIN32
DWORD WINAPI worker_thread(LPVOID arg) {
#else
void* worker_thread(void* arg) {
#endif
    thread_data_t* data = (thread_data_t*)arg;
    int completed = 0;
    
    printf("worker_thread %d (%s): started\n", data->thread_id, data->task_type);
    
    while (running && completed < data->iterations) {
        if (strcmp(data->task_type, "compute") == 0) {
            // computational work
            volatile long sum = 0;
            for (int i = 0; i < 500000; i++) {
                sum += i * data->thread_id;
            }
        } else if (strcmp(data->task_type, "memory") == 0) {
            // memory allocation/deallocation work
            char* buffer = malloc(1024 * data->thread_id);
            if (buffer) {
                memset(buffer, data->thread_id % 256, 1024 * data->thread_id);
                free(buffer);
            }
        } else if (strcmp(data->task_type, "io") == 0) {
            // simulate I/O work with longer sleeps
            usleep(100000); // 100ms
        }
        
        completed++;
        printf("worker_thread %d (%s): completed iteration %d/%d\n", 
               data->thread_id, data->task_type, completed, data->iterations);
        
        usleep(200000); // 200ms between iterations
    }
    
    printf("worker_thread %d (%s): finished after %d iterations\n", 
           data->thread_id, data->task_type, completed);
           
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int main() {
#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
#endif
    
    printf("multi_threaded_target: started (PID: %d)\n", getpid());
    printf("multi_threaded_target: main thread spawning workers...\n");
    
    // Define different types of work
    const char* task_types[] = {"compute", "memory", "io", "compute"};
    const int task_iterations[] = {6, 4, 8, 5};
    
#define NUM_THREADS 4
#ifdef _WIN32
    HANDLE threads[NUM_THREADS];
#else
    pthread_t threads[NUM_THREADS];
#endif
    thread_data_t thread_data[NUM_THREADS];
    
    // Main thread creates and manages worker threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i + 1;
        thread_data[i].task_type = task_types[i];
        thread_data[i].iterations = task_iterations[i];
        
        printf("main_thread: creating worker %d with task '%s' (%d iterations)\n", 
               thread_data[i].thread_id, thread_data[i].task_type, thread_data[i].iterations);
        
#ifdef _WIN32
        threads[i] = CreateThread(NULL, 0, worker_thread, &thread_data[i], 0, NULL);
        if (threads[i] == NULL) {
#else
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_data[i]) != 0) {
#endif
            printf("multi_threaded_target: failed to create thread %d\n", i + 1);
            exit(1);
        }
        
        // Main thread does some work between spawning threads
        printf("main_thread: performing coordination work...\n");
        volatile int main_work = 0;
        for (int j = 0; j < 100000; j++) {
            main_work += j;
        }
        usleep(50000); // 50ms delay between thread creation
    }
    
    printf("multi_threaded_target: main thread monitoring %d workers...\n", NUM_THREADS);
    
    // Main thread continues to do work while monitoring
    int monitor_cycles = 0;
    while (running && monitor_cycles < 20) {
        printf("main_thread: monitoring cycle %d\n", monitor_cycles + 1);
        
        // Do some monitoring work
        volatile int monitor_work = 0;
        for (int i = 0; i < 200000; i++) {
            monitor_work += i * monitor_cycles;
        }
        
        monitor_cycles++;
        usleep(300000); // 300ms between monitoring cycles
    }
    
    printf("main_thread: waiting for all workers to complete...\n");
    
    // Wait for all threads to complete
    for (int i = 0; i < NUM_THREADS; i++) {
#ifdef _WIN32
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif
        printf("main_thread: worker %d joined\n", i + 1);
    }
    
    printf("multi_threaded_target: all workers completed, main thread exiting\n");
    return 0;
}