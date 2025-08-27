#include "darwin_internal.hpp"

namespace w1::debugger::darwin {

result read_memory_impl(mach_port_t task_port, addr address, size_t size, std::vector<uint8_t>& out_data) {
  out_data.resize(size);
  mach_vm_size_t read_size = size;

  kern_return_t kr =
      mach_vm_read_overwrite(task_port, address.value, read_size, (mach_vm_address_t) out_data.data(), &read_size);

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to read memory", kr);
  }

  out_data.resize(read_size);
  return make_success_result();
}

result write_memory_impl(mach_port_t task_port, addr address, const std::vector<uint8_t>& data) {
  kern_return_t kr = mach_vm_write(task_port, address.value, (vm_offset_t) data.data(), data.size());

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to write memory", kr);
  }

  return make_success_result();
}

result get_memory_regions_impl(mach_port_t task_port, std::vector<memory_region>& out_regions) {
  (void) task_port;
  (void) out_regions;
  return make_error_result(error_code::not_implemented);
}

result allocate_memory_impl(mach_port_t task_port, size_t size, memory_prot prot, addr& out_address) {
  (void) task_port;
  (void) size;
  (void) prot;
  (void) out_address;
  return make_error_result(error_code::not_implemented);
}

result protect_memory_impl(mach_port_t task_port, addr address, size_t size, memory_prot prot) {
  (void) task_port;
  (void) address;
  (void) size;
  (void) prot;
  return make_error_result(error_code::not_implemented);
}

} // namespace w1::debugger::darwin
