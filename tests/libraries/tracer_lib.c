#include <stdio.h>
#include <time.h>
#include <stdlib.h>

// Forward declarations
void tracer_init();
void tracer_cleanup();

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define getpid _getpid

// DLL entry point for Windows
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            tracer_init();
            break;
        case DLL_PROCESS_DETACH:
            tracer_cleanup();
            break;
    }
    return TRUE;
}

void tracer_init() {
    time_t now = time(NULL);
    char time_str[26];
    ctime_s(time_str, sizeof(time_str), &now);
    time_str[24] = '\0'; // remove newline
    
    printf("TRACER: *** INJECTION SUCCESSFUL ***\n");
    printf("TRACER: library loaded at %s\n", time_str);
    printf("TRACER: target process PID: %d\n", getpid());
    
    // get module name on Windows
    char module_name[MAX_PATH];
    if (GetModuleFileNameA(NULL, module_name, MAX_PATH)) {
        printf("TRACER: target process image: %s\n", module_name);
    }
    
    printf("TRACER: initialization complete\n");
}

void tracer_cleanup() {
    time_t now = time(NULL);
    char time_str[26];
    ctime_s(time_str, sizeof(time_str), &now);
    time_str[24] = '\0'; // remove newline
    
    printf("TRACER: library unloaded at %s\n", time_str);
    printf("TRACER: cleanup complete\n");
}

#else
#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

// constructor function - called when library is loaded
__attribute__((constructor))
void tracer_init() {
    time_t now = time(NULL);
    char* time_str = ctime(&now);
    time_str[24] = '\0'; // remove newline
    
    printf("TRACER: *** INJECTION SUCCESSFUL ***\n");
    printf("TRACER: library loaded at %s\n", time_str);
    printf("TRACER: target process PID: %d\n", getpid());
    
#ifdef __APPLE__
    // get image name on macOS
    const char* image_name = _dyld_get_image_name(0);
    if (image_name) {
        printf("TRACER: target process image: %s\n", image_name);
    }
#elif defined(__linux__)
    // get process name on Linux
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", getpid());
    char exe_path[1024];
    ssize_t len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
    if (len != -1) {
        exe_path[len] = '\0';
        printf("TRACER: target process image: %s\n", exe_path);
    }
#endif
    
    printf("TRACER: initialization complete\n");
}

// destructor function - called when library is unloaded
__attribute__((destructor))
void tracer_cleanup() {
    time_t now = time(NULL);
    char* time_str = ctime(&now);
    time_str[24] = '\0'; // remove newline
    
    printf("TRACER: library unloaded at %s\n", time_str);
    printf("TRACER: cleanup complete\n");
}

#endif

// exported function that can be called from the target process
void tracer_report() {
    static int call_count = 0;
    call_count++;
    
    printf("TRACER: tracer_report() called %d times\n", call_count);
}