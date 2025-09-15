// minimal stub session implementation
#pragma once

#include "../w1debugger.hpp"

namespace w1::debugger::platform {

class stub_session final : public session {
public:
  explicit stub_session(target_info ti) : info_(std::move(ti)) {}
  ~stub_session() override = default;

  const target_info& info() const override { return info_; }
  std::expected<std::vector<module>, std::error_code> modules() override { return std::vector<module>{}; }

  std::expected<std::vector<tid_t>, std::error_code> threads() override { return std::vector<tid_t>{}; }
  std::expected<void, std::error_code> suspend(tid_t) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<void, std::error_code> resume(tid_t) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }

  std::expected<void, std::error_code> detach(detach_mode) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<void, std::error_code> terminate(int) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<void, std::error_code> continue_all() override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<void, std::error_code> step(tid_t, step_kind) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }

  std::expected<std::vector<reg_desc>, std::error_code> describe_registers(reg_class) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<register_file, std::error_code> read_registers(tid_t, reg_class) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<void, std::error_code> write_registers(tid_t, const register_file&, reg_class) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }

  std::expected<std::size_t, std::error_code> read_memory(addr_t, std::span<std::byte>) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<std::size_t, std::error_code> write_memory(addr_t, std::span<const std::byte>) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<std::vector<memory_region>, std::error_code> memory_map() override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<addr_t, std::error_code> allocate(std::size_t, page_prot) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<void, std::error_code> protect(addr_t, std::size_t, page_prot) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }

  std::expected<breakpoint_id, std::error_code> set_breakpoint(addr_t, const breakpoint_opts&) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<void, std::error_code> remove_breakpoint(breakpoint_id) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<watchpoint_id, std::error_code> set_watchpoint(addr_t, const watchpoint_opts&) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<void, std::error_code> remove_watchpoint(watchpoint_id) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }

  std::expected<debug_event, std::error_code> wait_for_event(std::optional<std::chrono::milliseconds>) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }
  std::expected<void, std::error_code> subscribe(event_callback) override {
    return std::unexpected(make_error_code(dbg_errc::not_supported));
  }

private:
  target_info info_{};
};

} // namespace w1::debugger::platform
