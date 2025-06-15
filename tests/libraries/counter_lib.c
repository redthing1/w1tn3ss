#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define getpid _getpid
static volatile LONG call_count = 0;

// Forward declarations
void counter_init();
void counter_cleanup();
void increment_counter();
int get_counter();

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            counter_init();
            break;
        case DLL_PROCESS_DETACH:
            counter_cleanup();
            break;
    }
    return TRUE;
}

void counter_init() {
    printf("COUNTER: library loaded into PID %d\n", getpid());
    printf("COUNTER: call count initialized to 0\n");
}

void counter_cleanup() {
    printf("COUNTER: library unloaded, final call count: %ld\n", call_count);
}

void increment_counter() {
    LONG count = InterlockedIncrement(&call_count);
    printf("COUNTER: call count = %ld\n", count);
}

#else
#include <unistd.h>

#ifdef __GNUC__
#include <stdatomic.h>
static atomic_int call_count = 0;
#else
static volatile int call_count = 0;
#endif

__attribute__((constructor))
void counter_init() {
    printf("COUNTER: library loaded into PID %d\n", getpid());
    printf("COUNTER: call count initialized to 0\n");
}

__attribute__((destructor))
void counter_cleanup() {
    printf("COUNTER: library unloaded, final call count: %d\n", call_count);
}

void increment_counter() {
#ifdef __GNUC__
    int count = atomic_fetch_add(&call_count, 1) + 1;
#else
    int count = ++call_count; // not thread-safe fallback
#endif
    printf("COUNTER: call count = %d\n", count);
}

#endif

// get current count without incrementing
int get_counter() {
    return call_count;
}