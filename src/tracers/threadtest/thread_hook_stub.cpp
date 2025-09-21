#include "thread_hook_internal.hpp"

namespace threadtest::hooking {

bool install_platform_hooks() { return false; }

void uninstall_platform_hooks() {}

} // namespace threadtest::hooking
