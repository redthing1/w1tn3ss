#!/bin/bash
# basic injection test script

set -e

echo "=== w1nj3ct injection test ==="

W1TOOL="./build-macos/w1tool"
PROGRAMS_DIR="./build-macos/tests/programs"
LIBRARIES_DIR="./build-macos/tests/libraries"

# check if tools exist
if [ ! -x "$W1TOOL" ]; then
    echo "error: w1tool not found - build first"
    exit 1
fi

if [ ! -d "$PROGRAMS_DIR" ]; then
    echo "error: test programs not found - build with tests enabled"
    exit 1
fi

echo "testing w1tool help:"
$W1TOOL --help
echo ""

# on macos, check if w1tool is signed
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "checking code signing status..."
    if codesign -dv "$W1TOOL" 2>/dev/null; then
        echo "w1tool is signed"
    else
        echo "warning: w1tool not signed - injection may fail"
        echo "run: ./tools/setup-macos.sh"
    fi
    echo ""
fi

echo "available test programs:"
ls -la "$PROGRAMS_DIR"
echo ""

echo "available test libraries:"
ls -la "$LIBRARIES_DIR"
echo ""

# test 1: simple runtime injection
echo "=== test: runtime injection ==="
echo "starting simple_target..."
$PROGRAMS_DIR/simple_target &
TARGET_PID=$!
echo "target pid: $TARGET_PID"

sleep 1

echo "attempting injection..."
if $W1TOOL inject --pid $TARGET_PID --library "$LIBRARIES_DIR/tracer_lib.dylib"; then
    echo "injection successful!"
else
    echo "injection failed (may need code signing on macos)"
fi

# cleanup
kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true
echo ""

# test 2: preload injection (unix only)
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "win32" ]]; then
    echo "=== test: preload injection ==="
    echo "launching with preloaded library..."
    if $W1TOOL inject --binary "$PROGRAMS_DIR/simple_target" --library "$LIBRARIES_DIR/tracer_lib.dylib"; then
        echo "preload successful!"
    else
        echo "preload failed"
    fi
    echo ""
fi

echo "=== tests complete ==="