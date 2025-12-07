// algorithmic demo resembling a mini crackme. safe and non-malicious.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t rotate_left(uint32_t value, unsigned int count) {
  return (value << (count % 32u)) | (value >> (32u - (count % 32u)));
}

static uint32_t mix_block(const char* block, size_t len, uint32_t seed) {
  uint32_t acc = seed;
  for (size_t i = 0; i < len; ++i) {
    acc ^= (uint8_t) block[i];
    acc = rotate_left(acc, (unsigned int) ((block[i] % 13) + 5));
    acc = acc * 0x45d9f3bu + 0x1337u;
  }
  return acc;
}

static uint32_t derive_key(const char* input) {
  uint32_t key = 0xDEADBEEFu;
  size_t len = strlen(input);
  for (size_t i = 0; i < len; i += 4) {
    key = mix_block(&input[i], (len - i) < 4 ? (len - i) : 4, key ^ (uint32_t) i);
  }
  return key;
}

static uint32_t evaluate_candidate(const char* candidate) {
  uint32_t key = derive_key(candidate);
  uint32_t score = 0;
  for (size_t i = 0; candidate[i] != '\0'; ++i) {
    score += (uint32_t) (candidate[i] * (int) (i + 7));
    score = rotate_left(score ^ key, (unsigned int) (i % 5 + 1));
  }
  return score ^ (uint32_t) strlen(candidate);
}

int main(void) {
  const char* const secrets[] = {
      "rew1nd-42",
      "rew1nd-43",
      "rew1nd-44",
  };

  uint32_t final_score = 0;
  for (size_t i = 0; i < sizeof(secrets) / sizeof(secrets[0]); ++i) {
    final_score ^= evaluate_candidate(secrets[i]) << (i * 3);
  }

  const char* attempt = "rew1nd-42";
  uint32_t attempt_score = evaluate_candidate(attempt);
  const int accepted = (attempt_score & 0xFFu) == (final_score & 0xFFu);

  printf("alg score=%u accepted=%d secret_xor=%u\n", attempt_score, accepted, final_score);
  return accepted ? 0 : 1;
}
