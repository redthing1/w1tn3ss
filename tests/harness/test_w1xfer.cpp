#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <redlog.hpp>
#include "w1base/cli/verbosity.hpp"

#include "tracers/w1xfer/transfer.hpp"

namespace {

int parse_verbosity(int argc, char* argv[]) {
  int verbose = 0;
  for (int i = 1; i < argc; ++i) {
    if (argv[i][0] != '-') {
      continue;
    }
    for (const char* p = argv[i]; *p; ++p) {
      if (*p == 'v') {
        ++verbose;
      }
    }
  }
  return verbose;
}

bool ensure_output_file(const std::string& path) {
  std::ifstream input(path);
  if (!input.is_open()) {
    return false;
  }
  std::string first_line;
  std::getline(input, first_line);
  return !first_line.empty();
}

} // namespace

// test function for w1xfer
extern "C" void* test_xfer_library_calls(void* arg) {
  size_t size = reinterpret_cast<size_t>(arg);

  void* buffer = malloc(size);
  if (!buffer) {
    printf("malloc failed for size %zu\n", size);
    return nullptr;
  }

  memset(buffer, 0x42, size);

  char message[256];
  snprintf(message, sizeof(message), "allocated and initialized %zu bytes at %p", size, buffer);
  printf("%s\n", message);

  FILE* fp = fopen("nonexistent_test_file_12345.txt", "r");
  if (fp) {
    printf("unexpectedly opened file\n");
    fclose(fp);
  } else {
    printf("expected file open failure\n");
  }

  free(buffer);
  return reinterpret_cast<void*>(size);
}

int main(int argc, char* argv[]) {
  const int verbose = parse_verbosity(argc, argv);
  w1::cli::apply_verbosity(verbose);

  w1xfer::transfer_config config;
  config.output.path = "test_w1xfer.jsonl";
  config.capture.registers = true;
  config.capture.stack = true;
  config.enrich.modules = true;
  config.enrich.symbols = true;
  config.enrich.analyze_apis = true;
  config.common.verbose = verbose;
  config.common.instrumentation.include_modules = {"test_w1xfer"};

  auto runtime = w1xfer::make_transfer_runtime(config);
  if (!runtime.session) {
    std::cerr << "failed to initialize w1xfer runtime\n";
    return 1;
  }

  uint64_t result = 0;
  if (!runtime.session->call_current_thread(reinterpret_cast<uint64_t>(test_xfer_library_calls), {1024}, &result)) {
    std::cerr << "failed to trace function\n";
    return 1;
  }

  runtime.session->export_output();

  const auto stats = runtime.session->engine().stats();
  if (stats.total_calls == 0 || stats.total_returns == 0) {
    std::cerr << "unexpected empty transfer stats\n";
    return 1;
  }

  if (!ensure_output_file(config.output.path)) {
    std::cerr << "output file missing or empty: " << config.output.path << "\n";
    return 1;
  }

  std::cout << "w1xfer test completed (output in " << config.output.path << ")\n";
  return 0;
}
