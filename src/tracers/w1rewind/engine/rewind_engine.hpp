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
#include "engine/module_table_builder.hpp"
#include "engine/register_schema.hpp"
#include "engine/trace_emitter.hpp"
#include "engine/target_environment_provider.hpp"
#include "w1instrument/core/module_registry.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1runtime/process_event.hpp"
#include "w1rewind/record/trace_builder.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"

namespace w1::util {
class register_state;
}

namespace w1rewind {

class rewind_engine {
public:
  explicit rewind_engine(rewind_config config);

  void configure(w1::runtime::module_catalog& modules);
  bool ensure_trace_ready(w1::trace_context& ctx, const w1::util::register_state& regs);

  bool trace_ready() const { return trace_ready_.load(std::memory_order_acquire); }
  bool instruction_flow() const { return instruction_flow_; }

  const rewind_config& config() const { return config_; }
  const register_schema& schema() const { return register_schema_; }
  const w1::arch::arch_spec& arch_spec() const { return arch_spec_; }

  bool begin_thread(uint64_t thread_id, const std::string& name);
  bool emit_block(uint64_t thread_id, uint64_t address, uint32_t size, uint32_t flags, uint64_t& sequence_out);
  void flush_pending(std::optional<pending_instruction>& pending);
  bool emit_snapshot(
      uint64_t thread_id, uint64_t sequence, uint64_t snapshot_id,
      std::span<const w1::rewind::register_delta> registers, std::span<const w1::rewind::stack_segment> stack_segments,
      std::string reason
  );
  void finalize_thread(uint64_t thread_id, const std::string& name, std::optional<pending_instruction>& pending);

  void on_process_event(const w1::runtime::process_event& event);

  bool export_trace();
  size_t module_count() const;
  std::string output_path() const;

private:
  using registry_type = w1::core::module_registry<w1::core::instrumented_module_policy, uint64_t>;

  bool start_trace_locked(w1::trace_context& ctx, const w1::util::register_state& regs);
  void rebuild_module_state_locked(const w1::runtime::module_catalog& modules);
  std::optional<w1::runtime::module_info> find_module_info(const w1::monitor::module_event& event) const;
  bool handle_module_loaded_locked(const w1::runtime::module_info& module);
  void handle_module_unloaded_locked(const w1::monitor::module_event& event);

  void upsert_module_record(w1::rewind::module_record record);
  std::optional<w1::rewind::module_record> remove_module_record(
      uint64_t module_id, uint64_t base, const std::string& path
  );

  bool emit_memory_map_locked();

  rewind_config config_{};
  registry_type registry_{};
  w1::runtime::module_catalog* modules_ = nullptr;

  w1::arch::arch_spec arch_spec_{};
  std::optional<module_metadata_cache> metadata_cache_;
  register_schema register_schema_{};

  std::shared_ptr<w1::rewind::trace_file_writer> writer_{};
  std::unique_ptr<w1::rewind::trace_builder> builder_{};
  std::unique_ptr<trace_emitter> emitter_{};

  std::vector<w1::rewind::module_record> module_table_{};

  redlog::logger log_;
  bool instruction_flow_ = false;
  bool configured_ = false;
  std::atomic<bool> trace_ready_{false};
  std::atomic<bool> trace_failed_{false};

  mutable std::mutex mutex_{};
};

} // namespace w1rewind
