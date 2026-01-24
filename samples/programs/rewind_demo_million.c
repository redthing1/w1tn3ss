// demo program to generate a few million basic block flow events. safe and non-malicious.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__clang__)
#define W1_NO_INLINE __attribute__((noinline))
#define W1_OPTNONE __attribute__((optnone))
#elif defined(__GNUC__)
#define W1_NO_INLINE __attribute__((noinline))
#define W1_OPTNONE
#else
#define W1_NO_INLINE
#define W1_OPTNONE
#endif

static W1_NO_INLINE W1_OPTNONE uint8_t rotl8(uint8_t value, unsigned int count) {
  const unsigned int r = count & 7u;
  if (r == 0u) {
    return value;
  }
  return (uint8_t) ((uint8_t) (value << r) | (uint8_t) (value >> (8u - r)));
}

static W1_NO_INLINE W1_OPTNONE uint32_t mix_slice(uint8_t* buffer, size_t len, uint32_t seed) {
  uint32_t acc = seed ^ 0x9e3779b9u;
  for (size_t i = 0; i < len; ++i) {
    acc ^= (uint32_t) (buffer[i] + (uint8_t) (i * 11u));
    acc = (acc << 7) | (acc >> 25);
    buffer[i] = (uint8_t) (buffer[i] + (uint8_t) (acc >> 3));
  }
  return acc;
}

static W1_NO_INLINE W1_OPTNONE uint64_t run_workload(uint8_t* buffer, size_t len, uint32_t iterations) {
  const uint32_t mask = (uint32_t) (len - 1u);
  uint32_t state = 0x1234567u;
  uint64_t acc = 0;

#if defined(__clang__)
#pragma clang loop vectorize(disable)
#pragma clang loop interleave(disable)
#endif
  for (uint32_t i = 0; i < iterations; ++i) {
    state = state * 1664525u + 1013904223u;
    const uint32_t idx = state & mask;
    const uint32_t alt = (idx + ((state >> 8) & mask)) & mask;

    switch (state & 3u) {
    case 0u:
      buffer[idx] ^= (uint8_t) state;
      acc += buffer[idx];
      break;
    case 1u:
      buffer[idx] = (uint8_t) (buffer[idx] + (uint8_t) (state >> 8));
      acc ^= (uint64_t) buffer[(idx + 1u) & mask];
      break;
    case 2u:
      buffer[idx] = rotl8(buffer[idx], (unsigned int) (state & 7u));
      acc += (uint64_t) (buffer[idx] * 3u);
      break;
    default:
      {
        uint8_t tmp = buffer[idx];
        buffer[idx] = buffer[alt];
        buffer[alt] = (uint8_t) (tmp ^ (uint8_t) (state >> 16));
        acc ^= (uint64_t) buffer[alt];
      }
      break;
    }

    if ((i & 1023u) == 0u) {
      acc ^= mix_slice(buffer, 16u, state);
    }
  }

  return acc;
}

int main(int argc, char** argv) {
  const uint32_t default_iterations = 1000000u;
  uint32_t iterations = default_iterations;
  if (argc > 1) {
    const unsigned long parsed = strtoul(argv[1], NULL, 10);
    if (parsed > 0u && parsed < 200000000u) {
      iterations = (uint32_t) parsed;
    }
  }

  uint8_t buffer[256];
  for (size_t i = 0; i < sizeof(buffer); ++i) {
    buffer[i] = (uint8_t) ((i * 37u) ^ 0xA5u);
  }

  const uint64_t acc = run_workload(buffer, sizeof(buffer), iterations);

  uint64_t checksum = acc;
  for (size_t i = 0; i < sizeof(buffer); ++i) {
    checksum += (uint64_t) buffer[i] * (uint64_t) (i + 1u);
  }

  printf("rewind million iterations=%u checksum=%llu\n", iterations, (unsigned long long) checksum);
  return (int) (checksum & 0xFFu);
}
