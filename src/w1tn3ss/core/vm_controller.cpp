#include "w1tn3ss/core/vm_controller.hpp"

namespace w1::core {

vm_controller::vm_controller() : owned_vm_(std::make_unique<QBDI::VM>()), vm_(owned_vm_.get()), owns_vm_(true) {}

vm_controller::vm_controller(QBDI::VM* borrowed_vm) : vm_(borrowed_vm), owns_vm_(false) {}

} // namespace w1::core
