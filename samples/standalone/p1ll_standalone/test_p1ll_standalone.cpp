#include "p1ll/p1ll.hpp"
#include <cstdlib>
#include <iostream>
#include <span>
#include <vector>

namespace {

void expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "test failed: " << message << std::endl;
    std::exit(1);
  }
}

} // namespace

int main() {
  std::vector<uint8_t> buffer(256, 0x90);

  // unique validation signature
  buffer[32] = 0xde;
  buffer[33] = 0xad;
  buffer[34] = 0xbe;
  buffer[35] = 0xef;

  // repeated signature for scan tests
  buffer[64] = 0x48;
  buffer[65] = 0x89;
  buffer[66] = 0xe5;
  buffer[128] = 0x48;
  buffer[129] = 0x89;
  buffer[130] = 0xe5;

  auto session = p1ll::engine::session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()));

  p1ll::engine::scan_options scan_opts;
  auto scan_results = session.scan("48 89 e5", scan_opts);
  expect(scan_results.ok(), "scan failed");
  expect(scan_results.value.size() >= 2, "expected multiple matches");

  p1ll::engine::scan_options single_opts;
  single_opts.single = true;
  auto single_results = session.scan("48 89 e5", single_opts);
  expect(!single_results.ok(), "single scan should fail on multiple matches");

  p1ll::engine::signature_spec validation;
  validation.pattern = "de ad be ef";
  validation.options.single = true;

  p1ll::engine::patch_spec patch;
  patch.signature = validation;
  patch.offset = 0;
  patch.patch = "11 22 33 44";
  patch.required = true;

  p1ll::engine::patch_spec optional_patch;
  optional_patch.signature.pattern = "00 11 22 33";
  optional_patch.signature.options.single = true;
  optional_patch.patch = "ff ff ff ff";
  optional_patch.required = false;

  p1ll::engine::recipe recipe;
  recipe.name = "buffer_patch";
  recipe.validations.push_back(validation);
  recipe.patches.push_back(patch);
  recipe.patches.push_back(optional_patch);

  auto plan = session.plan(recipe);
  expect(plan.ok(), "plan failed");
  expect(plan.value.size() == 1, "expected one plan entry");

  auto applied = session.apply(plan.value);
  expect(applied.ok(), "apply failed");
  expect(applied.value.success, "apply did not report success");
  expect(applied.value.applied == 1, "expected one applied entry");
  expect(applied.value.failed == 0, "expected zero failed entries");

  expect(buffer[32] == 0x11, "patch byte 0 mismatch");
  expect(buffer[33] == 0x22, "patch byte 1 mismatch");
  expect(buffer[34] == 0x33, "patch byte 2 mismatch");
  expect(buffer[35] == 0x44, "patch byte 3 mismatch");

  std::cout << "p1ll standalone test ok" << std::endl;
  return 0;
}
