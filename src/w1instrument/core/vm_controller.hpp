#pragma once

#include <memory>

#include <QBDI.h>

namespace w1::core {

class vm_controller {
public:
  vm_controller();
  explicit vm_controller(QBDI::VM* borrowed_vm);

  vm_controller(const vm_controller&) = delete;
  vm_controller& operator=(const vm_controller&) = delete;

  QBDI::VM* vm() const { return vm_; }
  bool owns_vm() const { return owns_vm_; }

private:
  std::unique_ptr<QBDI::VM> owned_vm_{};
  QBDI::VM* vm_ = nullptr;
  bool owns_vm_ = false;
};

} // namespace w1::core
