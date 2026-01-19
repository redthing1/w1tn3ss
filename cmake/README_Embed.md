# Embedding w1tn3ss components

This repository can be built as a full monorepo, or embedded as a subdirectory where only specific components are enabled. The embedding flow avoids pulling heavy dependencies unless the selected components need them.

## Embed only w1rewind

Add the repo root as a subdirectory, disable the full build, and enable the component you need.

Example CMakeLists.txt:

    cmake_minimum_required(VERSION 3.16)
    project(my_embed LANGUAGES CXX)

    set(W1_BUILD_ALL OFF CACHE BOOL "" FORCE)
    set(W1_BUILD_W1REWIND ON CACHE BOOL "" FORCE)
    add_subdirectory(path/to/w1tn3ss w1tn3ss_build)

    add_executable(my_app main.cpp)
    target_link_libraries(my_app PRIVATE w1::rewind::replay)

Targets provided:

- w1::rewind::format (alias: w1rewind::format)
- w1::rewind::record (alias: w1rewind::record)
- w1::rewind::replay (alias: w1rewind::replay)

## Embed the full repository but select components

Add the repo as a subdirectory and explicitly enable the components you need. When w1tn3ss is a subproject, all components default to OFF.

Example:

    set(W1_BUILD_ALL OFF CACHE BOOL "" FORCE)
    set(W1_BUILD_W1REWIND ON CACHE BOOL "" FORCE)
    set(W1_BUILD_W1REPLAY ON CACHE BOOL "" FORCE)
    add_subdirectory(path/to/w1tn3ss w1tn3ss_build)

Component options are named W1_BUILD_<COMPONENT>, where <COMPONENT> matches the directory name (uppercased). For example, W1_BUILD_W1REWIND, W1_BUILD_W1RUNTIME, W1_BUILD_TRACERS, and W1_BUILD_P1LL.

## Notes

- Heavy dependencies like QBDI and LIEF are only configured when a component that needs them is enabled.
- Use W1_USE_SYSTEM_DEPS=ON to prefer system-installed dependencies via find_package.
