# Tracers - w1 framework tracers

include("${WITNESS_CMAKE_DIR}/W1Tracers.cmake")
w1_dep_qbdi()

# add tracer subdirectories
add_subdirectory(w1cov)
add_subdirectory(w1dump)
add_subdirectory(w1rewind)
add_subdirectory(w1xfer)
add_subdirectory(w1script)
