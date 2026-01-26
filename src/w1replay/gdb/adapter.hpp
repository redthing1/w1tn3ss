#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gdbstub/server/server.hpp"
#include "gdbstub/target/target.hpp"

#include "adapter_components.hpp"
#include "adapter_services.hpp"
#include "thread_state.hpp"
#include "w1replay/modules/image_layout_provider.hpp"
#include "w1replay/modules/image_reader.hpp"
#include "w1replay/modules/address_index.hpp"

namespace w1replay {
class asmr_block_decoder;
}

namespace w1replay::gdb {

class adapter {
public:
  struct config {
    std::string trace_path;
    std::string index_path;
    std::string checkpoint_path;
    uint32_t index_stride = 0;
    uint64_t thread_id = 0;
    uint64_t start_sequence = 0;
    bool prefer_instruction_steps = false;
    std::vector<std::string> image_mappings;
    std::vector<std::string> image_dirs;
    image_layout_mode image_layout = image_layout_mode::trace;
    image_address_reader image_reader;
  };

  explicit adapter(config config);
  ~adapter();

  bool open();
  const std::string& error() const { return error_; }

  gdbstub::target make_target();
  const gdbstub::arch_spec& arch_spec() const { return arch_spec_; }
  bool track_memory() const { return track_memory_; }
  bool has_stack_snapshot() const { return has_stack_snapshot_; }

  const w1::rewind::replay_session& session() const;
  w1::rewind::replay_session& session();

private:
  bool load_context();
  bool open_session();
  bool prime_position();
  bool build_layout();
  bool build_arch_spec();
  bool build_target_xml();

  config config_;
  std::string error_;
  w1::rewind::replay_context context_{};
  std::shared_ptr<w1::rewind::trace_record_stream> stream_;
  std::shared_ptr<w1::rewind::trace_index> index_;
  std::shared_ptr<w1::rewind::replay_checkpoint_index> checkpoint_;
  std::optional<w1::rewind::replay_session> session_;
  register_layout layout_{};
  std::string target_xml_;
  gdbstub::arch_spec arch_spec_{};
  int pc_reg_num_ = -1;
  endian target_endian_ = endian::little;
  bool trace_is_block_ = false;
  bool decoder_available_ = false;
  bool track_memory_ = false;
  bool has_stack_snapshot_ = false;
  breakpoint_store breakpoints_{};
  std::unique_ptr<w1replay::asmr_block_decoder> decoder_;
  std::unique_ptr<image_path_resolver> image_resolver_;
  std::shared_ptr<image_layout_provider> image_layout_provider_;
  std::shared_ptr<image_reader> image_reader_;
  std::shared_ptr<image_metadata_provider> image_metadata_provider_;
  std::unique_ptr<memory_view> memory_view_;
  std::unique_ptr<loaded_libraries_provider> loaded_libraries_provider_;
  std::unique_ptr<image_address_index> image_index_;
  adapter_services services_{};
  thread_state thread_state_{};

  std::unique_ptr<regs_component> regs_component_;
  std::unique_ptr<mem_component> mem_component_;
  std::unique_ptr<run_component> run_component_;
  std::unique_ptr<breakpoints_component> breakpoints_component_;
  std::unique_ptr<threads_component> threads_component_;
  std::unique_ptr<host_info_component> host_info_component_;
  std::unique_ptr<memory_layout_component> memory_layout_component_;
  std::unique_ptr<libraries_component> libraries_component_;
  std::unique_ptr<loaded_libraries_component> loaded_libraries_component_;
  std::unique_ptr<process_info_component> process_info_component_;
  std::unique_ptr<auxv_component> auxv_component_;
  std::unique_ptr<offsets_component> offsets_component_;
  std::unique_ptr<register_info_component> register_info_component_;
};

} // namespace w1replay::gdb
