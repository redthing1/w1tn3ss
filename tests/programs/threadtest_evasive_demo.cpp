// threadtest_evasive_demo exercises thread creation paths that bypass our pthread hooks.
// this program is strictly for validating instrumentation coverage against evasive behavior.
// it does not perform any malicious action and is used to test our analysis tools.

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#if defined(_WIN32)
int main() {
  std::fprintf(stderr, "threadtest_evasive_demo is not supported on Windows.\n");
  return EXIT_SUCCESS;
}
#elif defined(__APPLE__)

#include <atomic>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <mach/thread_state.h>
#include <pthread.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <vector>

extern "C" void __bsdthread_terminate(void*, void*, uint32_t, uint32_t);

// shared completion counter so the main thread can wait for every worker
static std::atomic<int> g_completed_threads{0};

struct worker_payload {
  const char* tag;
  int iterations;
};

// simple workload that burns some cpu time and emits a status line
static void sleep_millis(int millis) {
  if (millis <= 0) {
    return;
  }

  struct timespec ts;
  ts.tv_sec = millis / 1000;
  ts.tv_nsec = (millis % 1000) * 1000000L;
  while (nanosleep(&ts, &ts) != 0) {
    // retry when interrupted
  }
}

static void perform_work(const worker_payload& payload, bool allow_sleep, bool emit_log) {
  volatile uint64_t accumulator = 0;
  for (int i = 0; i < payload.iterations; ++i) {
    accumulator += static_cast<uint64_t>((i + 1) * 13);
    if (allow_sleep && (i % 4) == 0) {
      sleep_millis(30);
    }
  }

  if (emit_log) {
    std::printf("[%s] work complete (acc=%llu)\n", payload.tag, static_cast<unsigned long long>(accumulator));
  }
  g_completed_threads.fetch_add(1, std::memory_order_release);
}

// -- standard pthread_create -------------------------------------------------

static void* pthread_worker_entry(void* arg) {
  const worker_payload* payload = static_cast<const worker_payload*>(arg);
  perform_work(*payload, /*allow_sleep=*/true, /*emit_log=*/true);
  return nullptr;
}

static bool launch_plain_pthread(worker_payload& payload, pthread_t* out_thread) {
  int rc = pthread_create(out_thread, nullptr, &pthread_worker_entry, &payload);
  if (rc != 0) {
    std::fprintf(stderr, "pthread_create failed: %d\n", rc);
    return false;
  }
  return true;
}

// -- pthread_create_suspended_np path ----------------------------------------

static void* suspended_worker_entry(void* arg) {
  const worker_payload* payload = static_cast<const worker_payload*>(arg);
  perform_work(*payload, /*allow_sleep=*/true, /*emit_log=*/true);
  return nullptr;
}

static bool launch_suspended_pthread(worker_payload& payload, pthread_t* out_thread) {
  int rc = pthread_create_suspended_np(out_thread, nullptr, &suspended_worker_entry, &payload);
  if (rc != 0) {
    std::fprintf(stderr, "pthread_create_suspended_np failed: %d\n", rc);
    return false;
  }

  // resume the thread so it starts executing without going through pthread_create
  thread_act_t thread_port = pthread_mach_thread_np(*out_thread);
  kern_return_t kr = thread_resume(thread_port);
  if (kr != KERN_SUCCESS) {
    std::fprintf(stderr, "thread_resume failed: %d\n", kr);
    return false;
  }
  return true;
}

// -- direct mach thread via thread_create_running ----------------------------

struct mach_thread_allocation {
  mach_port_t thread_port;
  mach_vm_address_t stack_address;
  mach_vm_size_t stack_size;
};

struct mach_thread_payload {
  worker_payload payload;
};

static void mach_thread_entry(void* raw_arg) {
  mach_thread_payload* thread_payload = static_cast<mach_thread_payload*>(raw_arg);
  perform_work(thread_payload->payload, /*allow_sleep=*/false, /*emit_log=*/false);

  const char* msg = "[mach_thread_create] work complete\n";
  write(STDOUT_FILENO, msg, strlen(msg));

  delete thread_payload;

  // exit without relying on pthread teardown APIs
  __bsdthread_terminate(nullptr, nullptr, 0, 0);
}

static bool launch_mach_thread(const worker_payload& payload, mach_thread_allocation& allocation) {
  allocation.stack_address = 0;
  allocation.stack_size = 0;
  allocation.thread_port = MACH_PORT_NULL;

  // allocate a private stack for the mach thread
  const mach_vm_size_t stack_size = (1u << 20); // 1 MiB
  mach_vm_address_t stack_base = 0;
  kern_return_t kr = mach_vm_allocate(mach_task_self(), &stack_base, stack_size, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) {
    std::fprintf(stderr, "mach_vm_allocate failed: %d\n", kr);
    return false;
  }

  mach_vm_address_t stack_top = stack_base + stack_size - 0x10;

  auto* thread_payload = new mach_thread_payload{payload};

#if defined(__aarch64__)
  arm_thread_state64_t state = {};
  uint64_t entry = reinterpret_cast<uint64_t>(&mach_thread_entry);
#if defined(__arm64e__)
  entry = reinterpret_cast<uint64_t>(__builtin_ptrauth_strip(reinterpret_cast<void*>(&mach_thread_entry), 0));
#endif
  state.__pc = entry;
  state.__sp = stack_top;
  state.__x[0] = reinterpret_cast<uint64_t>(thread_payload);
  state.__lr = 0;
  mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
  thread_state_flavor_t flavor = ARM_THREAD_STATE64;
#elif defined(__x86_64__)
  x86_thread_state64_t state = {};
  state.__rip = reinterpret_cast<uint64_t>(&mach_thread_entry);
  state.__rsp = stack_top;
  state.__rdi = reinterpret_cast<uint64_t>(thread_payload);
  state.__rbp = 0;
  mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
  thread_state_flavor_t flavor = x86_THREAD_STATE64;
#else
#error "unsupported darwin architecture"
#endif

  mach_port_t thread_port = MACH_PORT_NULL;
  kr = thread_create_running(
      mach_task_self(), flavor, reinterpret_cast<thread_state_t>(&state), state_count, &thread_port
  );
  if (kr != KERN_SUCCESS) {
    std::fprintf(stderr, "thread_create_running failed: %d\n", kr);
    delete thread_payload;
    mach_vm_deallocate(mach_task_self(), stack_base, stack_size);
    return false;
  }

  allocation.stack_address = stack_base;
  allocation.stack_size = stack_size;
  allocation.thread_port = thread_port;
  return true;
}

// -- dispatch workqueue path --------------------------------------------------

struct dispatch_payload {
  worker_payload payload;
};

static void dispatch_worker(void* context) {
  auto* payload = static_cast<dispatch_payload*>(context);
  perform_work(payload->payload, /*allow_sleep=*/true, /*emit_log=*/true);
  delete payload;
}

static bool launch_dispatch_worker(const worker_payload& payload, dispatch_queue_t queue) {
  auto* context = new dispatch_payload{payload};
  dispatch_async_f(queue, context, &dispatch_worker);
  return true;
}

int main() {
  std::vector<mach_thread_allocation> mach_allocations;
  mach_allocations.reserve(2);

  worker_payload pthread_payload{"pthread_create", 12};
  worker_payload suspended_payload{"pthread_create_suspended_np", 10};
  worker_payload mach_payload{"mach_thread_create", 14};
  worker_payload dispatch_payload_data{"dispatch_async", 8};

  pthread_t plain_thread{};
  pthread_t suspended_thread{};

  if (!launch_plain_pthread(pthread_payload, &plain_thread)) {
    return EXIT_FAILURE;
  }

  if (!launch_suspended_pthread(suspended_payload, &suspended_thread)) {
    // ensure the first thread is joined before exiting
    pthread_join(plain_thread, nullptr);
    return EXIT_FAILURE;
  }

  mach_thread_allocation mach_allocation{};
  if (launch_mach_thread(mach_payload, mach_allocation)) {
    mach_allocations.push_back(mach_allocation);
  } else {
    std::fprintf(stderr, "mach thread launch failed\n");
  }

  dispatch_queue_t queue = dispatch_queue_create("com.w1tn3ss.threadtest.evasive", DISPATCH_QUEUE_CONCURRENT);
  launch_dispatch_worker(dispatch_payload_data, queue);

  // join the pthread-based workers to keep the demo tidy
  pthread_join(plain_thread, nullptr);
  pthread_join(suspended_thread, nullptr);

  const int expected = 4;
  while (g_completed_threads.load(std::memory_order_acquire) < expected) {
    sleep_millis(50);
  }

  // clean up any mach resources we own
  for (const auto& allocation : mach_allocations) {
    if (allocation.thread_port != MACH_PORT_NULL) {
      mach_port_deallocate(mach_task_self(), allocation.thread_port);
    }
    if (allocation.stack_address != 0 && allocation.stack_size != 0) {
      mach_vm_deallocate(mach_task_self(), allocation.stack_address, allocation.stack_size);
    }
  }

#if !OS_OBJECT_USE_OBJC
  dispatch_release(queue);
#endif

  std::printf("threadtest_evasive_demo complete\n");
  return EXIT_SUCCESS;
}

#else
int main() {
  std::fprintf(stderr, "threadtest_evasive_demo is only implemented for Darwin targets.\n");
  return EXIT_SUCCESS;
}
#endif
