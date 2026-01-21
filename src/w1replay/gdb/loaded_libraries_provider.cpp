#include "loaded_libraries_provider.hpp"

#include "w1rewind/replay/replay_context.hpp"

#include "w1replay/modules/metadata_provider.hpp"
#include "w1replay/modules/path_resolver.hpp"
#include "w1replay/gdb/lldb/darwin_loaded_libraries.hpp"

namespace w1replay::gdb {

std::unique_ptr<loaded_libraries_provider> make_loaded_libraries_provider(
    const w1::rewind::replay_context& context, module_metadata_provider& metadata_provider,
    module_path_resolver& resolver
) {
  if (context.target_info.has_value() && context.target_info->os == "macos") {
    return std::make_unique<darwin_loaded_libraries_provider>(context, metadata_provider, resolver);
  }
  return nullptr;
}

} // namespace w1replay::gdb
