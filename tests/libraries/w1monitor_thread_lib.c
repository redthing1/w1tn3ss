#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#if defined(_WIN32)
#define W1MONITOR_EXPORT __declspec(dllexport)
#elif defined(__APPLE__)
#define W1MONITOR_EXPORT __attribute__((visibility("default")))
#else
#define W1MONITOR_EXPORT __attribute__((visibility("default")))
#endif

struct thread_payload {
  atomic_uint_fast64_t* tid_out;
  const char* name;
};

static void* w1monitor_thread_proc(void* arg) {
  struct thread_payload* payload = (struct thread_payload*) arg;
  uint64_t tid = 0;
#if defined(__linux__)
  tid = (uint64_t) syscall(SYS_gettid);
#endif
  if (payload && payload->tid_out) {
    atomic_store_explicit(payload->tid_out, tid, memory_order_release);
  }
  if (payload && payload->name) {
    (void) pthread_setname_np(pthread_self(), payload->name);
  }
  free(payload);

  struct timespec ts;
  ts.tv_sec = 0;
  ts.tv_nsec = 50 * 1000 * 1000;
  (void) nanosleep(&ts, NULL);

  return NULL;
}

W1MONITOR_EXPORT int w1monitor_spawn_thread(pthread_t* thread_out, uint64_t* tid_out, const char* name) {
  if (!thread_out || !tid_out) {
    return EINVAL;
  }

  atomic_uint_fast64_t tid_storage;
  atomic_init(&tid_storage, 0);

  struct thread_payload* payload = (struct thread_payload*) malloc(sizeof(*payload));
  if (!payload) {
    return ENOMEM;
  }
  payload->tid_out = &tid_storage;
  payload->name = name;

  const int result = pthread_create(thread_out, NULL, w1monitor_thread_proc, payload);
  if (result != 0) {
    free(payload);
    return result;
  }

  while (atomic_load_explicit(&tid_storage, memory_order_acquire) == 0) {
    sched_yield();
  }

  *tid_out = (uint64_t) atomic_load_explicit(&tid_storage, memory_order_acquire);
  return 0;
}

W1MONITOR_EXPORT int w1monitor_join_thread(pthread_t thread) { return pthread_join(thread, NULL); }
