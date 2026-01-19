set(THREADTEST_SOURCES
    preload.cpp
    threadtest_tracer.cpp
)

w1_add_tracer(threadtest
    SOURCES ${THREADTEST_SOURCES}
)
