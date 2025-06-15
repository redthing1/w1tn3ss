#!/bin/bash
#
# Linux Testing Suite Runner
# Comprehensive testing for Linux injection functionality
#

set -e

# Configuration
BUILD_DIR="${1:-build-linux}"
VERBOSE=""
TEST_RUNTIME=""
TEST_PRELOAD="--test-preload"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE="--verbose"
            shift
            ;;
        --test-runtime)
            TEST_RUNTIME="--test-runtime"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--build-dir DIR] [--verbose] [--test-runtime] [--help]"
            echo ""
            echo "Options:"
            echo "  --build-dir DIR    Build directory (default: build-linux)"
            echo "  --verbose          Enable verbose output"
            echo "  --test-runtime     Test runtime injection (requires privileges)"
            echo "  --help             Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Basic tests"
            echo "  $0 --build-dir build-debug --verbose # Debug build with verbose output"
            echo "  $0 --test-runtime                     # Include runtime injection tests"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    error "This test suite requires Linux"
    exit 1
fi

# Check build directory
if [[ ! -d "$BUILD_DIR" ]]; then
    error "Build directory '$BUILD_DIR' does not exist"
    exit 1
fi

# Check w1tool
if [[ ! -x "$BUILD_DIR/w1tool" ]]; then
    error "w1tool not found or not executable in '$BUILD_DIR'"
    exit 1
fi

info "Starting Linux injection testing suite"
info "Build directory: $BUILD_DIR"
info "Platform: $(uname -s) $(uname -r)"
info "Architecture: $(uname -m)"
info "User: $(whoami) (UID: $(id -u))"

# Check capabilities
if [[ -f /proc/sys/kernel/yama/ptrace_scope ]]; then
    PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope)
    info "Ptrace scope: $PTRACE_SCOPE"
    if [[ "$PTRACE_SCOPE" != "0" ]] && [[ $(id -u) != "0" ]]; then
        warning "Runtime injection may require elevated privileges (ptrace_scope=$PTRACE_SCOPE)"
    fi
fi

# Check capabilities with capsh if available
if command -v capsh >/dev/null 2>&1; then
    if capsh --print 2>/dev/null | grep -q cap_sys_ptrace; then
        success "CAP_SYS_PTRACE capability available"
    else
        warning "CAP_SYS_PTRACE capability not available"
    fi
fi

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    info "Running: $test_name"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval "$test_command"; then
        success "$test_name: PASSED"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        error "$test_name: FAILED"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test 1: Basic Linux injection functionality
run_test "Linux Injection Tests" \
    "python3 ./tests/test_linux_injection.py --build-dir '$BUILD_DIR' $VERBOSE $TEST_RUNTIME $TEST_PRELOAD"

# Test 2: Linux backend integration tests
run_test "Linux Backend Integration Tests" \
    "python3 ./tests/integration/test_linux_backend.py --build-dir '$BUILD_DIR' $VERBOSE"

# Test 3: Cross-platform compatibility (if available)
if [[ -f "./tests/test_w1cov.py" ]]; then
    run_test "w1cov Coverage Tests (Linux)" \
        "python3 ./tests/test_w1cov.py --build-dir '$BUILD_DIR'"
fi

# Test 4: Basic w1tool functionality
run_test "W1tool Basic Functionality" \
    "$BUILD_DIR/w1tool --help >/dev/null && $BUILD_DIR/w1tool inspect --list-processes >/dev/null"

# Test 5: Library resolution test
if [[ -f "$BUILD_DIR/tests/libraries/tracer_lib.so" ]]; then
    run_test "Library Resolution Test" \
        "ldd '$BUILD_DIR/tests/libraries/tracer_lib.so' >/dev/null"
else
    warning "tracer_lib.so not found, skipping library resolution test"
fi

# Test 6: Test programs functionality
if [[ -x "$BUILD_DIR/tests/programs/simple_target" ]]; then
    run_test "Test Programs Execution" \
        "timeout 5 '$BUILD_DIR/tests/programs/simple_target' >/dev/null || true"
else
    warning "simple_target not found, skipping execution test"
fi

# Print summary
echo ""
info "=== Linux Testing Suite Summary ==="
info "Total tests: $TOTAL_TESTS"
success "Passed: $PASSED_TESTS"
if [[ $FAILED_TESTS -gt 0 ]]; then
    error "Failed: $FAILED_TESTS"
else
    info "Failed: $FAILED_TESTS"
fi

SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
info "Success rate: ${SUCCESS_RATE}%"

# Provide recommendations
echo ""
if [[ $FAILED_TESTS -eq 0 ]]; then
    success "All tests passed! Linux injection functionality is working correctly."
elif [[ $SUCCESS_RATE -ge 80 ]]; then
    warning "Most tests passed. Check failed tests for minor issues."
else
    error "Several tests failed. Linux injection functionality may have issues."
fi

# Permission recommendations
if [[ $(id -u) != "0" ]] && [[ "$PTRACE_SCOPE" != "0" ]]; then
    echo ""
    warning "For full testing capabilities, consider:"
    warning "  - Running as root: sudo $0 $*"
    warning "  - Or temporarily allowing ptrace: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope"
    warning "  - Or setting CAP_SYS_PTRACE capability"
fi

# Exit with appropriate code
if [[ $FAILED_TESTS -eq 0 ]]; then
    exit 0
else
    exit 1
fi