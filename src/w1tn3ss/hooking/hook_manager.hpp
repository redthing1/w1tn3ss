#pragma once

#include <QBDI.h>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>
#include <string>
#include <redlog.hpp>

namespace w1::util {
class module_range_index;
struct module_info;
}

namespace w1::hooking {

// hook handler type - receives raw QBDI objects
using hook_handler = std::function<QBDI::VMAction(QBDI::VMInstanceRef, QBDI::GPRState*, QBDI::FPRState*, QBDI::rword)>;

class hook_manager {
public:
  explicit hook_manager(QBDI::VM* vm) : vm_(vm) {}
  ~hook_manager();

  // hook registration
  uint32_t hook_addr(QBDI::rword address, hook_handler handler);
  uint32_t hook_module(const std::string& module_name, QBDI::rword offset, hook_handler handler);
  uint32_t hook_range(QBDI::rword start, QBDI::rword end, hook_handler handler);

  // hook management
  bool remove_hook(uint32_t hook_id);
  void remove_all_hooks();

private:
  struct hook_info {
    uint32_t id;
    hook_handler handler;
    uint32_t qbdi_id = QBDI::INVALID_EVENTID;
    QBDI::rword address = 0;                            // for single address hooks
    std::pair<QBDI::rword, QBDI::rword> range = {0, 0}; // for range hooks
  };

  QBDI::VM* vm_;
  uint32_t next_hook_id_ = 1;
  std::unordered_map<uint32_t, hook_info> hooks_;
  redlog::logger log_{"w1.hook_manager"};

  // helper methods
  const w1::util::module_info* find_module_with_extensions(
      const w1::util::module_range_index& module_index, const std::string& module_name
  ) const;

  // QBDI callback wrapper
  static QBDI::VMAction hook_callback_wrapper(
      QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
  );
};

} // namespace w1::hooking