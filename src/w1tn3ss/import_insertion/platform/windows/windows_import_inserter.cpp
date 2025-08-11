#include "windows_import_inserter.hpp"
#include <redlog.hpp>

namespace w1::import_insertion::windows {

result insert_library_import(const config& cfg) {
    auto log = redlog::get_logger("w1.import_insertion.windows");
    log.error("windows library import insertion not yet implemented");
    
    return result{
        .code = error_code::platform_not_supported,
        .error_message = "windows library import insertion not yet supported"
    };
}

bool check_import_capabilities() {
    return false;
}

} // namespace w1::import_insertion::windows