#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

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

#ifdef _WIN32
DWORD WINAPI worker_thread(LPVOID arg) {
#else
void* worker_thread(void* arg) {
#endif
    int thread_id = *(int*)arg;
    int iterations = 0;
    
    printf("worker_thread %d: started\n", thread_id);
    
    while (running) {
        printf("worker_thread %d: iteration %d\n", thread_id, iterations++);
        
        // simulate some work
        volatile int sum = 0;
        for (int i = 0; i < 100000; i++) {
            sum += i * thread_id;
        }
        
        usleep(500000); // 500ms
        
        if (iterations >= 8) {
            printf("worker_thread %d: completed max iterations, exiting\n", thread_id);
            break;
        }
    }
    
    printf("worker_thread %d: finished after %d iterations\n", thread_id, iterations);
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
    
#define NUM_THREADS 4
#ifdef _WIN32
    HANDLE threads[NUM_THREADS];
#else
    pthread_t threads[NUM_THREADS];
#endif
    int thread_ids[NUM_THREADS];
    
    // create worker threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i + 1;
#ifdef _WIN32
        threads[i] = CreateThread(NULL, 0, worker_thread, &thread_ids[i], 0, NULL);
        if (threads[i] == NULL) {
#else
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_ids[i]) != 0) {
#endif
            printf("multi_threaded_target: failed to create thread %d\n", i + 1);
            exit(1);
        }
    }
    
    printf("multi_threaded_target: created %d worker threads\n", NUM_THREADS);
    
    // wait for all threads to complete
    for (int i = 0; i < NUM_THREADS; i++) {
#ifdef _WIN32
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif
        printf("multi_threaded_target: thread %d joined\n", i + 1);
    }
    
    printf("multi_threaded_target: all threads completed, exiting\n");
    return 0;
}