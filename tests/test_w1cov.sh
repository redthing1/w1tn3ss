#!/bin/bash

# W1COV Testing Script
# Tests core coverage functionality

BUILD_DIR="build-release"
W1TOOL="$BUILD_DIR/w1tool"
W1COV_LIB="$BUILD_DIR/w1cov_qbdipreload.dylib"
TEST_PROGRAMS_DIR="$BUILD_DIR/tests/programs"

# Create temp directory and ensure cleanup
cd "$(dirname "$0")/.."  # Go to project root
mkdir -p temp
TEMP_DIR="temp"

cleanup() {
    rm -f "$TEMP_DIR"/*.drcov 2>/dev/null || true
}

trap cleanup EXIT

echo "=== W1COV Testing ==="

# Test 1: Simple target coverage
echo "Testing simple target..."
cd "$TEMP_DIR"
timeout 10s "../$W1TOOL" inject \
    --tool w1cov \
    --library "../$W1COV_LIB" \
    --binary "../$TEST_PROGRAMS_DIR/simple_target" \
    >/dev/null 2>&1

if [ -f "simple_target.drcov" ]; then
    bb_count=$(strings "simple_target.drcov" | grep "BB Table:" | sed 's/BB Table: //; s/ bbs//' 2>/dev/null || echo "0")
    echo "Simple target: $bb_count basic blocks"
else
    echo "Simple target: FAILED"
    exit 1
fi
cd ..

# Test 2: Multi-threaded target coverage
echo "Testing multi-threaded target..."
cd "$TEMP_DIR"
timeout 10s "../$W1TOOL" inject \
    --tool w1cov \
    --library "../$W1COV_LIB" \
    --binary "../$TEST_PROGRAMS_DIR/multi_threaded_target" \
    >/dev/null 2>&1

if [ -f "multi_threaded_target.drcov" ]; then
    bb_count=$(strings "multi_threaded_target.drcov" | grep "BB Table:" | sed 's/BB Table: //; s/ bbs//' 2>/dev/null || echo "0")
    echo "Multi-threaded target: $bb_count basic blocks"
else
    echo "Multi-threaded target: FAILED"
    exit 1
fi
cd ..

# Test 3: Complex interactive program
echo "Testing control flow program..."
cd "$TEMP_DIR"
echo "test input" | timeout 15s "../$W1TOOL" inject \
    --tool w1cov \
    --library "../$W1COV_LIB" \
    --binary "../$TEST_PROGRAMS_DIR/control_flow_1" \
    >/dev/null 2>&1

if [ -f "control_flow_1.drcov" ]; then
    bb_count=$(strings "control_flow_1.drcov" | grep "BB Table:" | sed 's/BB Table: //; s/ bbs//' 2>/dev/null || echo "0")
    echo "Control flow: $bb_count basic blocks"
else
    echo "Control flow: FAILED"
    exit 1
fi
cd ..

echo "All tests completed successfully"