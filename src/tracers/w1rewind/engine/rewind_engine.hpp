#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "config/rewind_config.hpp"
#include "engine/image_inventory.hpp"
#include "engine/image_inventory_pipeline.hpp"
#include "engine/register_schema.hpp"
#include "engine/register_schema_provider.hpp"
#include "engine/trace_emitter.hpp"
#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/record/trace_builder.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"

namespace w1::util {
class register_state;
}

namespace w1rewind {

class rewind_engine {
public:
  explicit rewind_engine(rewind_config config);

  void configure(std::shared_ptr<image_inventory_provider> provider);
  bool ensure_trace_ready(const w1::util::register_state& regs);

  bool trace_ready() const { return trace_ready_.load(std::memory_order_acquire); }
  bool instruction_flow() const { return instruction_flow_; }

  const rewind_config& config() const { return config_; }
  const register_schema& schema() const { return register_schema_; }
  void set_register_schema(std::vector<w1::rewind::register_spec> specs);
  void set_register_schema_provider(std::shared_ptr<register_schema_provider> provider);
  void set_arch_descriptor(w1::rewind::arch_descriptor_record arch);
  void set_environment_record(w1::rewind::environment_record env);
  const w1::rewind::arch_descriptor_record& arch_descriptor() const { return arch_desc_; }
  w1::rewind::endian byte_order() const { return arch_desc_.byte_order; }
  uint16_t resolve_mode_id(const w1::util::register_state* regs) const;

  bool begin_thread(uint64_t thread_id, const std::string& name);
  bool emit_block(
      uint64_t thread_id, uint64_t address, uint32_t size, uint32_t space_id, uint16_t mode_id,
      uint64_t& sequence_out
  );
  void flush_pending(std::optional<pending_instruction>& pending);
  bool emit_snapshot(
      uint64_t thread_id, uint64_t sequence, uint64_t snapshot_id,
      std::span<const w1::rewind::reg_write_entry> registers,
      std::span<const w1::rewind::memory_segment> memory_segments
  );
  void finalize_thread(uint64_t thread_id, const std::string& name, std::optional<pending_instruction>& pending);

  void on_image_event(const image_inventory_event& event);
  std::shared_ptr<image_inventory_provider> image_provider() const { return image_provider_; }

  bool export_trace();
  size_t image_count() const;
  std::string output_path() const;

private:
  bool start_trace_locked(const w1::util::register_state& regs);

  rewind_config config_{};
  std::shared_ptr<image_inventory_provider> image_provider_{};
  std::shared_ptr<register_schema_provider> register_schema_provider_{};

  w1::rewind::arch_descriptor_record arch_desc_{};
  w1::rewind::environment_record environment_record_{};
  bool arch_configured_ = false;
  bool environment_configured_ = false;
  register_schema register_schema_{};

  std::shared_ptr<w1::rewind::trace_file_writer> writer_{};
  std::unique_ptr<w1::rewind::trace_builder> builder_{};
  std::unique_ptr<trace_emitter> emitter_{};

  redlog::logger log_;
  image_inventory_pipeline image_pipeline_;
  bool instruction_flow_ = false;
  bool configured_ = false;
  std::atomic<bool> trace_ready_{false};
  std::atomic<bool> trace_failed_{false};

  mutable std::mutex mutex_{};
};

} // namespace w1rewind
