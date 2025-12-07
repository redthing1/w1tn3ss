// demo program covering memcpy/memmove/memset patterns. safe and non-malicious.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t accumulate(const uint8_t* data, size_t size) {
  uint32_t acc = 0;
  for (size_t i = 0; i < size; ++i) {
    acc = (acc << 5) ^ (acc >> 2) ^ data[i];
  }
  return acc;
}

int main(void) {
  uint8_t src[96];
  uint8_t dst[96];
  for (size_t i = 0; i < sizeof(src); ++i) {
    src[i] = (uint8_t) ((i * 13u) ^ 0x5Au);
  }
  memset(dst, 0, sizeof(dst));

  // overlapping move
  memmove(dst + 8, src, 64);
  memmove(dst + 24, dst + 8, 40);
  memset(dst + 12, 0xA5, 8);

  uint8_t* heap = (uint8_t*) malloc(160);
  if (heap == NULL) {
    return 1;
  }
  memset(heap, 0, 160);
  memcpy(heap + 16, dst, 48);
  memmove(heap + 32, heap + 16, 64);

  // small struct copy via memcpy
  struct pair {
    uint32_t a;
    uint32_t b;
  } pairs[6];
  for (size_t i = 0; i < 6; ++i) {
    pairs[i].a = (uint32_t) (i * 0x11111111u);
    pairs[i].b = accumulate(src + i * 4, 4);
  }
  memcpy(heap + 96, pairs, sizeof(pairs));

  uint32_t digest = accumulate(dst, sizeof(dst));
  digest ^= accumulate(heap, 160);
  digest ^= accumulate((const uint8_t*) pairs, sizeof(pairs));

  printf("memops digest=%08x\n", digest);
  free(heap);
  return (int) (digest & 0xFF);
}
