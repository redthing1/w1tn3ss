// demo program exercising stdio-style I/O for the rewind tracer. safe and non-malicious.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void synthesize_line(char* buffer, size_t size, uint32_t seed) {
  for (size_t i = 0; i < size - 1; ++i) {
    buffer[i] = (char) ('A' + (int) ((seed + i * 7u) % 26u));
  }
  buffer[size - 1] = '\0';
}

int main(void) {
  char line1[32];
  char line2[32];
  synthesize_line(line1, sizeof(line1), 1234u);
  synthesize_line(line2, sizeof(line2), 9876u);

  FILE* temp = tmpfile();
  if (temp == NULL) {
    return 1;
  }
  setvbuf(temp, NULL, _IOLBF, 0);

  fputs(line1, temp);
  fputc('\n', temp);
  fwrite(line2, 1, strlen(line2), temp);
  fflush(temp);

  fseek(temp, 0, SEEK_SET);
  char readback[64];
  size_t read_total = fread(readback, 1, sizeof(readback) - 1, temp);
  readback[read_total] = '\0';
  fclose(temp);

  uint32_t checksum = 0;
  for (size_t i = 0; i < read_total; ++i) {
    checksum = (checksum * 131u) ^ (uint8_t) readback[i];
  }

  printf("io digest=%u len=%zu\n", checksum, read_total);
  return (int) (checksum & 0xFF);
}
