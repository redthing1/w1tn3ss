#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32)
int main(void) {
  fprintf(stderr, "threadtest_demo is not supported on Windows.\n");
  return EXIT_SUCCESS;
}
#else

#include <pthread.h>
#include <unistd.h>

typedef struct worker_args {
  int index;
  int iterations;
} worker_args;

static void random_delay(void) {
  struct timespec ts;
  ts.tv_sec = 0;
  ts.tv_nsec = (rand() % 200 + 50) * 1000000; // 50-250ms
  nanosleep(&ts, NULL);
}

static void* worker_thread(void* arg) {
  worker_args* args = (worker_args*) arg;
  long accumulator = 0;
  for (int i = 0; i < args->iterations; ++i) {
    accumulator += (args->index + 1) * (i + 1);
    if ((i % 3) == 0) {
      random_delay();
    }
  }

  printf("worker %d done: iterations=%d sum=%ld\n", args->index, args->iterations, accumulator);
  fflush(stdout);

  return (void*) (uintptr_t) accumulator;
}

int main(void) {
  srand((unsigned int) time(NULL));

  const int thread_count = 3;
  pthread_t threads[thread_count];
  worker_args args[thread_count];

  for (int i = 0; i < thread_count; ++i) {
    args[i].index = i;
    args[i].iterations = 10 + (i * 5);
    int rc = pthread_create(&threads[i], NULL, worker_thread, &args[i]);
    if (rc != 0) {
      fprintf(stderr, "pthread_create failed for thread %d: %d\n", i, rc);
      return EXIT_FAILURE;
    }
  }

  for (int i = 0; i < thread_count; ++i) {
    void* result = NULL;
    int rc = pthread_join(threads[i], &result);
    if (rc != 0) {
      fprintf(stderr, "pthread_join failed for thread %d: %d\n", i, rc);
      continue;
    }
    printf("worker %d result=%ld\n", i, (long) (uintptr_t) result);
  }

  printf("threadtest_demo complete\n");
  return EXIT_SUCCESS;
}

#endif
