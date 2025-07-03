#include <stdio.h>
#include <stdint.h>

// simple test target for p1ll binary patching validation
// contains predictable patterns that can be found and patched

void license_check() {
    // function with conditional jump that can be patched
    uint64_t license_status = 0;  // 0 = trial, 1 = licensed
    
    if (license_status == 0) {
        printf("TRIAL VERSION - Please purchase a license\n");
    } else {
        printf("Licensed version - Thank you!\n");
    }
}

void demo_message() {
    // function with string that can be patched
    printf("DEMO VERSION - Limited functionality\n");
}

void validation_routine() {
    // another function with patchable logic
    int validation_result = 0;  // 0 = fail, 1 = pass
    
    if (validation_result != 1) {
        printf("Validation failed - Access denied\n");
    } else {
        printf("Validation passed - Full access granted\n");
    }
}

int main() {
    printf("p1ll test target v1.0\n");
    printf("=====================\n\n");
    
    license_check();
    demo_message();
    validation_routine();
    
    printf("\ntest target completed.\n");
    return 0;
}