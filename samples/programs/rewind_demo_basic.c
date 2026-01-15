// demo program for validating the rewind tracer. this code is safe and not malicious.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct simple_record {
  uint32_t checksum;
  uint32_t count;
  uint8_t history[16];
};

static void update_record(struct simple_record* record, uint8_t value) {
  const size_t slot = record->count % sizeof(record->history);
  record->history[slot] = (uint8_t) (value ^ record->checksum);
  record->count += 1;
  record->checksum = (record->checksum << 1) ^ (uint32_t) (value * 0x45u + 0x33u);
  record->checksum ^= (uint32_t) (record->history[(slot + 7u) % sizeof(record->history)] * 17u);
}

#if defined(__clang__)
__attribute__((optnone))
#endif
static uint32_t sum_bytes(const uint8_t* data, size_t size) {
  uint32_t total = 0;
  for (size_t i = 0; i < size; ++i) {
    total += data[i];
  }
  return total;
}

int main(void) {
  struct simple_record record = {0};
  uint8_t buffer[32];
  uint8_t shadow[32];
  memset(buffer, 0, sizeof(buffer));
  memset(shadow, 0, sizeof(shadow));

#if defined(__clang__)
#pragma clang loop vectorize(disable)
#pragma clang loop interleave(disable)
#endif
  for (uint8_t i = 0; i < 20; ++i) {
    update_record(&record, (uint8_t) (i * 7u));
    buffer[i % sizeof(buffer)] = (uint8_t) (record.checksum & 0xFFu);
    shadow[(i * 5u) % sizeof(shadow)] = (uint8_t) (record.checksum >> 8);
  }

  // exercise common memory primitives with overlapping regions
  memmove(buffer + 4, buffer, 12);
  memcpy(shadow + 8, buffer + 8, 16);
  memset(buffer + 20, (int) record.history[3], 6);

  const uint32_t total = sum_bytes(buffer, sizeof(buffer));
  const uint32_t shadow_total = sum_bytes(shadow, sizeof(shadow));

  printf("record checksum=%u, count=%u, total=%u, shadow=%u\n", record.checksum, record.count, total, shadow_total);
  return (int) ((record.checksum ^ total ^ shadow_total) & 0xFF);
}
