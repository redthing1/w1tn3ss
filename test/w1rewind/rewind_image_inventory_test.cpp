#include <algorithm>
#include <filesystem>
#include <string>

#include "doctest/doctest.hpp"

#include "engine/image_inventory.hpp"
#include "engine/qbdi_register_schema_provider.hpp"
#include "engine/rewind_engine.hpp"
#include "w1base/arch_spec.hpp"
#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/trace/trace_reader.hpp"
#include "w1runtime/register_capture.hpp"

namespace {

class stub_inventory_provider final : public w1rewind::image_inventory_provider {
public:
  void reset(const w1::rewind::arch_descriptor_record&) override { reset_called = true; }

  w1rewind::image_inventory_snapshot snapshot(uint32_t space_id) override {
    w1rewind::image_inventory_snapshot snapshot;
    w1::rewind::image_record image{};
    image.image_id = 100;
    image.name = "stub_image";
    snapshot.images.push_back(image);

    w1::rewind::mapping_record mapping{};
    mapping.space_id = space_id;
    mapping.base = 0x1000;
    mapping.size = 0x200;
    mapping.image_id = image.image_id;
    snapshot.mappings.push_back(mapping);
    return snapshot;
  }

  std::optional<w1rewind::image_inventory_event> translate_event(
      const w1rewind::image_inventory_source_event&, uint32_t
  ) override {
    return std::nullopt;
  }

  bool reset_called = false;
};

const char* set_test_register(QBDI::GPRState& gpr, uint64_t value) {
#if defined(QBDI_ARCH_X86_64)
  gpr.rax = value;
  return "rax";
#elif defined(QBDI_ARCH_X86)
  gpr.eax = static_cast<uint32_t>(value);
  return "eax";
#elif defined(QBDI_ARCH_AARCH64)
  gpr.x0 = value;
  return "x0";
#elif defined(QBDI_ARCH_ARM)
  gpr.r0 = static_cast<uint32_t>(value);
  return "r0";
#else
  (void) gpr;
  (void) value;
  return "";
#endif
}

struct register_capture_result {
  std::string name;
  w1::util::register_state regs;
};

register_capture_result capture_test_state(uint64_t value) {
  QBDI::GPRState gpr{};
  const char* name = set_test_register(gpr, value);
  return {name, w1::util::register_capturer::capture(&gpr)};
}

std::string arch_mode_name(w1::arch::mode mode) {
  switch (mode) {
  case w1::arch::mode::x86_64:
    return "x86_64";
  case w1::arch::mode::x86_32:
    return "x86_32";
  case w1::arch::mode::arm:
    return "arm";
  case w1::arch::mode::thumb:
    return "thumb";
  case w1::arch::mode::aarch64:
    return "aarch64";
  case w1::arch::mode::riscv32:
    return "riscv32";
  case w1::arch::mode::riscv64:
    return "riscv64";
  case w1::arch::mode::mips32:
    return "mips32";
  case w1::arch::mode::mips64:
    return "mips64";
  case w1::arch::mode::ppc32:
    return "ppc32";
  case w1::arch::mode::ppc64:
    return "ppc64";
  case w1::arch::mode::sparc32:
    return "sparc32";
  case w1::arch::mode::sparc64:
    return "sparc64";
  case w1::arch::mode::systemz:
    return "systemz";
  case w1::arch::mode::wasm32:
    return "wasm32";
  case w1::arch::mode::wasm64:
    return "wasm64";
  default:
    break;
  }
  return "unknown";
}

} // namespace

TEST_CASE("rewind_engine rejects configure without arch descriptor") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  w1rewind::rewind_config config{};
  fs::path trace_path = temp_path("w1rewind_inventory_no_arch.trace");
  config.output_path = trace_path.string();

  auto provider = std::make_shared<stub_inventory_provider>();
  w1rewind::rewind_engine engine(config);
  engine.configure(provider);

  CHECK_FALSE(provider->reset_called);
  CHECK(engine.image_count() == 0);

  std::error_code ec;
  fs::remove(trace_path, ec);
}

TEST_CASE("rewind_engine uses image inventory provider snapshots and events") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  w1rewind::rewind_config config{};
  fs::path trace_path = temp_path("w1rewind_inventory.trace");
  config.output_path = trace_path.string();

  auto provider = std::make_shared<stub_inventory_provider>();
  w1rewind::rewind_engine engine(config);
  auto arch = parse_arch_or_fail("x86_64");
  engine.set_arch_descriptor(make_arch_descriptor("x86_64", arch));
  engine.set_environment_record(make_environment());
  engine.configure(provider);

  CHECK(provider->reset_called);
  CHECK(engine.image_count() == 1);

  w1::rewind::image_record extra{};
  extra.image_id = 200;
  extra.name = "extra_image";
  w1::rewind::mapping_record extra_map{};
  extra_map.space_id = 0;
  extra_map.base = 0x4000;
  extra_map.size = 0x100;
  extra_map.image_id = extra.image_id;

  w1rewind::image_inventory_event loaded{};
  loaded.kind = w1rewind::image_inventory_event_kind::loaded;
  loaded.image_id = extra.image_id;
  loaded.image = extra;
  loaded.mappings.push_back(extra_map);
  engine.on_image_event(loaded);

  CHECK(engine.image_count() == 2);

  w1rewind::image_inventory_event unloaded{};
  unloaded.kind = w1rewind::image_inventory_event_kind::unloaded;
  unloaded.image_id = extra.image_id;
  unloaded.mappings.push_back(extra_map);
  engine.on_image_event(unloaded);

  CHECK(engine.image_count() == 1);

  engine.export_trace();
  std::error_code ec;
  fs::remove(trace_path, ec);
}

TEST_CASE("rewind_engine refuses to start trace without environment record") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  w1rewind::rewind_config config{};
  fs::path trace_path = temp_path("w1rewind_inventory_no_env.trace");
  config.output_path = trace_path.string();

  auto provider = std::make_shared<stub_inventory_provider>();
  w1rewind::rewind_engine engine(config);
  auto arch = parse_arch_or_fail("x86_64");
  engine.set_arch_descriptor(make_arch_descriptor("x86_64", arch));
  engine.configure(provider);

  w1::util::register_state regs;
  CHECK_FALSE(engine.ensure_trace_ready(regs));
  CHECK_FALSE(engine.trace_ready());

  engine.export_trace();
  std::error_code ec;
  fs::remove(trace_path, ec);
}

TEST_CASE("rewind_engine rejects register specs wider than 64 bits") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  w1rewind::rewind_config config{};
  fs::path trace_path = temp_path("w1rewind_register_width.trace");
  config.output_path = trace_path.string();
  config.registers.deltas = true;

  auto provider = std::make_shared<stub_inventory_provider>();
  w1rewind::rewind_engine engine(config);
  auto arch = w1::arch::detect_host_arch_spec();
  auto arch_desc = make_arch_descriptor(arch_mode_name(arch.arch_mode), arch);
  engine.set_arch_descriptor(arch_desc);
  engine.set_environment_record(make_environment());
  engine.configure(provider);

  auto capture = capture_test_state(0x1234);
  REQUIRE(!capture.name.empty());

  w1rewind::qbdi_register_schema_provider schema_provider;
  std::vector<w1::rewind::register_spec> specs;
  std::string error;
  REQUIRE(schema_provider.build_register_schema(arch_desc, specs, error));

  auto it = std::find_if(specs.begin(), specs.end(), [&](const auto& spec) { return spec.name == capture.name; });
  REQUIRE(it != specs.end());
  it->bit_size = 128;
  engine.set_register_schema(std::move(specs));

  CHECK_FALSE(engine.ensure_trace_ready(capture.regs));
  CHECK_FALSE(engine.trace_ready());

  std::error_code ec;
  fs::remove(trace_path, ec);
}

TEST_CASE("rewind_engine unmaps by space id and size") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  w1rewind::rewind_config config{};
  fs::path trace_path = temp_path("w1rewind_unmap_match.trace");
  config.output_path = trace_path.string();

  auto provider = std::make_shared<stub_inventory_provider>();
  w1rewind::rewind_engine engine(config);
  auto arch = w1::arch::detect_host_arch_spec();
  auto arch_desc = make_arch_descriptor(arch_mode_name(arch.arch_mode), arch);
  engine.set_arch_descriptor(arch_desc);
  engine.set_environment_record(make_environment());
  engine.configure(provider);

  w1::util::register_state regs;
  REQUIRE(engine.ensure_trace_ready(regs));

  w1::rewind::image_record image{};
  image.image_id = 42;
  image.name = "test_image";

  w1::rewind::mapping_record map_a{};
  map_a.space_id = 0;
  map_a.base = 0x1000;
  map_a.size = 0x100;
  map_a.image_id = image.image_id;

  w1::rewind::mapping_record map_b{};
  map_b.space_id = 1;
  map_b.base = 0x1000;
  map_b.size = 0x200;
  map_b.image_id = image.image_id;

  w1rewind::image_inventory_event loaded{};
  loaded.kind = w1rewind::image_inventory_event_kind::loaded;
  loaded.image_id = image.image_id;
  loaded.image = image;
  loaded.mappings = {map_a, map_b};
  engine.on_image_event(loaded);

  w1rewind::image_inventory_event unload_b{};
  unload_b.kind = w1rewind::image_inventory_event_kind::unloaded;
  unload_b.image_id = image.image_id;
  unload_b.mappings = {map_b};
  engine.on_image_event(unload_b);

  w1rewind::image_inventory_event unload_a{};
  unload_a.kind = w1rewind::image_inventory_event_kind::unloaded;
  unload_a.image_id = image.image_id;
  unload_a.mappings = {map_a};
  engine.on_image_event(unload_a);

  engine.export_trace();

  w1::rewind::trace_reader reader(trace_path.string());
  REQUIRE(reader.open());

  size_t unmap_count = 0;
  bool saw_a = false;
  bool saw_b = false;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (!std::holds_alternative<w1::rewind::mapping_record>(record)) {
      continue;
    }
    const auto& mapping = std::get<w1::rewind::mapping_record>(record);
    if (mapping.kind != w1::rewind::mapping_event_kind::unmap) {
      continue;
    }
    unmap_count += 1;
    if (mapping.space_id == 0 && mapping.base == 0x1000 && mapping.size == 0x100) {
      saw_a = true;
    }
    if (mapping.space_id == 1 && mapping.base == 0x1000 && mapping.size == 0x200) {
      saw_b = true;
    }
  }
  CHECK(reader.error().empty());
  CHECK(unmap_count == 2);
  CHECK(saw_a);
  CHECK(saw_b);

  std::error_code ec;
  fs::remove(trace_path, ec);
}
