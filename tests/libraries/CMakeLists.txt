# test injection libraries

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

set(TEST_LIBRARY_OUTPUT_SUBDIR libraries)

function(w1_add_test_library target source)
    add_library(${target} SHARED ${source})
    set_target_properties(${target} PROPERTIES PREFIX "")
    w1_set_test_output_dirs(${target} ${TEST_LIBRARY_OUTPUT_SUBDIR})
    w1_disable_sanitizers(${target})
endfunction()

w1_add_test_library(tracer_lib tracer_lib.c)
w1_add_test_library(counter_lib counter_lib.c)
w1_add_test_library(memory_lib memory_lib.c)
w1_add_test_library(w1h00k_interpose_lib w1h00k_interpose_lib.c)
w1_add_test_library(w1cov_demo_lib w1cov_demo_lib.c)

if(UNIX AND NOT APPLE)
    w1_add_test_library(linux_test_lib linux_test_lib.c)
    target_link_libraries(linux_test_lib PRIVATE ${CMAKE_DL_LIBS})
endif()

# platform-specific linking and suffixes
if(WIN32)
    target_link_libraries(memory_lib PRIVATE psapi)
    set(TEST_LIBRARY_SUFFIX ".dll")
elseif(APPLE)
    set(TEST_LIBRARY_SUFFIX ".dylib")
else()
    set(TEST_LIBRARY_SUFFIX ".so")
endif()

set(TEST_LIBRARY_TARGETS tracer_lib counter_lib memory_lib w1h00k_interpose_lib w1cov_demo_lib)
if(TARGET linux_test_lib)
    list(APPEND TEST_LIBRARY_TARGETS linux_test_lib)
endif()

foreach(target IN LISTS TEST_LIBRARY_TARGETS)
    set_target_properties(${target} PROPERTIES SUFFIX "${TEST_LIBRARY_SUFFIX}")
endforeach()

if(TARGET w1h00k_tests)
    add_dependencies(w1h00k_tests w1h00k_interpose_lib)
endif()
if(TARGET w1monitor_tests)
    add_dependencies(w1monitor_tests w1h00k_interpose_lib)
endif()
if(TARGET test_monitor_demo)
    add_dependencies(test_monitor_demo w1h00k_interpose_lib)
endif()

install(TARGETS ${TEST_LIBRARY_TARGETS}
    LIBRARY DESTINATION test/libraries
    RUNTIME DESTINATION test/libraries
    COMPONENT ${W1_TESTS_COMPONENT}
)
