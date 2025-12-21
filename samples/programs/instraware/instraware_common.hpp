#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace instraware {

struct result {
  std::string test_id;
  std::string platform;
  std::string arch;
  uint64_t iterations = 0;
  double score = 0.0;
  double confidence = 0.0;
  uint64_t anomalies = 0;
  std::string notes;
};

struct args {
  uint64_t iterations = 1000;
  const char* json_out = nullptr;
  bool verbose = false;
};

uint64_t now_ns();
const char* platform();
const char* arch();
args parse_args(int argc, char** argv);
FILE* open_output(const char* path);
void close_output(FILE* file);
void emit_json(const result& entry, FILE* out);

} // namespace instraware
