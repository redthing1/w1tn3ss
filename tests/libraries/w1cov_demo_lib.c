#include <stdint.h>

#if defined(_WIN32) || defined(WIN32)
#include <windows.h>
#define W1COV_EXPORT __declspec(dllexport)
#define W1COV_CALL WINAPI
#else
#define W1COV_EXPORT __attribute__((visibility("default")))
#define W1COV_CALL
#endif

W1COV_EXPORT int w1cov_demo_add(int a, int b) {
  int result = a + b;
  if (result & 1) {
    result += 3;
  } else {
    result -= 2;
  }
  return result;
}

W1COV_EXPORT int w1cov_demo_branch(int value) {
  int out = 0;
  if (value < 0) {
    out = -value;
  } else if (value < 10) {
    out = value * 2;
  } else if (value < 100) {
    out = value * 3;
    if (value % 2 == 0) {
      out += 5;
    } else {
      out -= 7;
    }
  } else {
    out = value / 4;
  }
  return out;
}

#if defined(_WIN32) || defined(WIN32)
W1COV_EXPORT DWORD W1COV_CALL w1cov_demo_thread_proc(LPVOID param) {
  int value = (int)(intptr_t)param;
  int sum = 0;
  for (int i = 0; i < value; ++i) {
    sum += w1cov_demo_add(i, value);
    if ((sum & 1) == 0) {
      sum ^= 0x55;
    }
  }
  sum += w1cov_demo_branch(value);
  return (DWORD)sum;
}
#else
W1COV_EXPORT void* W1COV_CALL w1cov_demo_thread_proc(void* param) {
  int value = (int)(intptr_t)param;
  int sum = 0;
  for (int i = 0; i < value; ++i) {
    sum += w1cov_demo_add(i, value);
    if ((sum & 1) == 0) {
      sum ^= 0x55;
    }
  }
  sum += w1cov_demo_branch(value);
  return (void*)(intptr_t)sum;
}
#endif
