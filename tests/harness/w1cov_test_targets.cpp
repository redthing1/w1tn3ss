#include <cstdint>

extern "C" uint64_t test_coverage_control_flow(uint64_t value) {
  uint64_t result = 0;

  if (value < 10) {
    result = value * 2;
  } else if (value < 20) {
    result = value * 3;
    if (value % 2 == 0) {
      result += 5;
    } else {
      result -= 3;
    }
  } else if (value < 50) {
    for (int i = 0; i < 10; i++) {
      result += i;
      if (result > 100) {
        break;
      }
    }
  } else {
    switch (value % 4) {
    case 0:
      result = value / 2;
      break;
    case 1:
      result = value * value;
      break;
    case 2:
      result = value + 100;
      break;
    default:
      result = value - 50;
      break;
    }
  }

  if (result > 0) {
    if (result % 2 == 0) {
      result = result / 2;
    } else {
      result = result * 3 + 1;
    }
  }

  return result;
}
