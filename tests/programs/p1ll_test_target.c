#include <stdint.h>
#include <stdio.h>

// simple test target for p1ll binary patching validation
// contains predictable patterns that can be found and patched

void platform_info() {
// function with platform-specific information

// arch
#if defined(__x86_64__)
  printf("Platform: x86_64\n");
#elif defined(__aarch64__)
  printf("Platform: aarch64\n");
#elif defined(__i386__)
  printf("Platform: i386\n");
#endif

// os
#if defined(__linux__)
  printf("OS: Linux\n");
#elif defined(__APPLE__)
  printf("OS: macOS\n");
#elif defined(_WIN32)
  printf("OS: Windows\n");
#endif
}

void license_check() {
  // function with conditional jump that can be patched
  uint64_t license_status = 0; // 0 = trial, 1 = licensed

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
  int validation_result = 0; // 0 = fail, 1 = pass

  if (validation_result != 1) {
    printf("Validation failed - Access denied\n");
  } else {
    printf("Validation passed - Full access granted\n");
  }
}

int main() {
  printf("p1ll test target v1.0\n");
  printf("=====================\n\n");

  platform_info();
  license_check();
  demo_message();
  validation_routine();

  printf("\ntest target completed.\n");
  return 0;
}
