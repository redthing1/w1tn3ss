#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// forward declarations
void report_memory_usage();
void memory_init();
void memory_cleanup();

#ifdef _WIN32
#include <windows.h>

#include <process.h>
#include <psapi.h>
#define getpid _getpid

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            memory_init();
            break;
        case DLL_PROCESS_DETACH:
            memory_cleanup();
            break;
    }
    return TRUE;
}

void memory_init() {
    printf("MEMORY: library loaded into PID %d\n", getpid());
    report_memory_usage();
}

void memory_cleanup() {
    printf("MEMORY: library unloaded\n");
    report_memory_usage();
}

void report_memory_usage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        printf("MEMORY: working set: %zu KB\n", pmc.WorkingSetSize / 1024);
        printf("MEMORY: page file usage: %zu KB\n", pmc.PagefileUsage / 1024);
        printf("MEMORY: peak working set: %zu KB\n", pmc.PeakWorkingSetSize / 1024);
    } else {
        printf("MEMORY: unable to get memory info\n");
    }
}

#else
#include <unistd.h>
#include <sys/resource.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/task.h>
#endif

#ifdef __linux__
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

__attribute__((constructor))
void memory_init() {
    printf("MEMORY: library loaded into PID %d\n", getpid());
    report_memory_usage();
}

__attribute__((destructor))
void memory_cleanup() {
    printf("MEMORY: library unloaded\n");
    report_memory_usage();
}

void report_memory_usage() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        printf("MEMORY: max resident set size: %ld KB\n", usage.ru_maxrss);
#ifdef __APPLE__
        // macOS reports in bytes
        printf("MEMORY: current RSS: %ld KB\n", usage.ru_maxrss / 1024);
#else
        // Linux reports in KB
        printf("MEMORY: current RSS: %ld KB\n", usage.ru_maxrss);
#endif
    }

#ifdef __APPLE__
    // get more detailed memory info on macOS
    struct task_basic_info info;
    mach_msg_type_number_t size = TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &size) == KERN_SUCCESS) {
        printf("MEMORY: virtual size: %lu KB\n", (unsigned long)(info.virtual_size / 1024));
        printf("MEMORY: resident size: %lu KB\n", (unsigned long)(info.resident_size / 1024));
    }
#endif

#ifdef __linux__
    // read from /proc/self/status on Linux
    FILE* status = fopen("/proc/self/status", "r");
    if (status) {
        char line[256];
        while (fgets(line, sizeof(line), status)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                printf("MEMORY: %s", line);
            } else if (strncmp(line, "VmSize:", 7) == 0) {
                printf("MEMORY: %s", line);
            }
        }
        fclose(status);
    }
#endif
}

#endif

// allocate some memory for testing
void* allocate_test_memory(size_t size) {
    void* ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0xAA, size); // fill with pattern
        printf("MEMORY: allocated %zu bytes at %p\n", size, ptr);
        report_memory_usage();
    }
    return ptr;
}

void free_test_memory(void* ptr) {
    if (ptr) {
        printf("MEMORY: freeing memory at %p\n", ptr);
        free(ptr);
        report_memory_usage();
    }
}