#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#endif

// Global state for the application
static volatile int g_running = 1;
static volatile int g_counter = 0;
static volatile int g_operations_performed = 0;

// Different algorithms to create interesting code paths
int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

void bubble_sort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

void string_operations() {
    char buffer[256];
    const char* words[] = {"hello", "world", "coverage", "testing", "runtime", "injection"};
    int word_count = sizeof(words) / sizeof(words[0]);
    
    strcpy(buffer, "Runtime injection test: ");
    
    for (int i = 0; i < 3; i++) {
        strcat(buffer, words[rand() % word_count]);
        if (i < 2) strcat(buffer, " ");
    }
    
    printf("[%d] %s (length: %zu)\n", g_counter, buffer, strlen(buffer));
}

void mathematical_operations() {
    int a = rand() % 10 + 1;
    int b = rand() % 10 + 1;
    
    int fib_result = fibonacci(a);
    int fact_result = factorial(b);
    
    printf("[%d] Math: fib(%d)=%d, fact(%d)=%d\n", g_counter, a, fib_result, b, fact_result);
}

void array_operations() {
    int size = rand() % 10 + 5;
    int* arr = malloc(size * sizeof(int));
    
    // Fill with random data
    for (int i = 0; i < size; i++) {
        arr[i] = rand() % 100;
    }
    
    printf("[%d] Sorting array of %d elements: ", g_counter, size);
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    
    bubble_sort(arr, size);
    
    printf("-> ");
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
    
    free(arr);
}

void* worker_thread(void* arg) {
    int thread_id = *(int*)arg;
    int local_counter = 0;
    
    while (g_running) {
        local_counter++;
        
        if (local_counter % 5 == 0) {
            printf("[Thread %d] Background work iteration %d\n", thread_id, local_counter);
        }
        
        // Do some work to create coverage
        int temp = fibonacci(5) + factorial(3);
        temp = temp % 100;  // Use the result
        
#ifdef _WIN32
        Sleep(500);  // 0.5 second
#else
        usleep(500000);  // 0.5 second
#endif
    }
    
    printf("[Thread %d] Exiting after %d iterations\n", thread_id, local_counter);
    return NULL;
}

void print_status() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    printf("\n=== Runtime Injection Target Status ===\n");
    printf("PID: %d\n", getpid());
    printf("Operations performed: %d\n", g_operations_performed);
    printf("Current counter: %d\n", g_counter);
    printf("Timestamp: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
    printf("Ready for runtime injection testing!\n");
    printf("=======================================\n\n");
}

int main() {
#ifdef _WIN32
    printf("Starting runtime injection target (PID: %d)\n", _getpid());
#else
    printf("Starting runtime injection target (PID: %d)\n", getpid());
#endif
    printf("This program will run continuously until interrupted.\n");
    printf("Use w1tool to inject coverage collection while it's running.\n\n");
    
    srand(time(NULL));
    
#ifndef _WIN32
    // Start background worker thread (Unix only)
    pthread_t worker;
    int thread_id = 1;
    pthread_create(&worker, NULL, worker_thread, &thread_id);
#endif
    
    print_status();
    
    // Main loop with different operation types
    while (g_running) {
        g_counter++;
        
        // Cycle through different types of operations
        switch (g_counter % 4) {
            case 0:
                string_operations();
                break;
            case 1:
                mathematical_operations();
                break;
            case 2:
                array_operations();
                break;
            case 3:
                printf("[%d] Simple operation: %d + %d = %d\n", 
                       g_counter, g_counter, g_counter * 2, g_counter + g_counter * 2);
                break;
        }
        
        g_operations_performed++;
        
        // Print status periodically
        if (g_counter % 10 == 0) {
            print_status();
        }
        
        // Stop after a reasonable number of operations for testing
        if (g_counter >= 50) {
            printf("\nReached operation limit, shutting down gracefully...\n");
            g_running = 0;
        }
        
#ifdef _WIN32
        Sleep(1000);  // 1 second between operations
#else
        sleep(1);  // 1 second between operations
#endif
    }
    
#ifndef _WIN32
    // Wait for worker thread to finish (Unix only)
    pthread_join(worker, NULL);
#endif
    
    printf("\nRuntime injection target completed.\n");
    printf("Total operations performed: %d\n", g_operations_performed);
    
    return 0;
}