// demo program for exercising nested calls under the rewind tracer. safe and non-malicious.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

struct frame_state {
  int32_t values[8];
};

static void seed_frame(struct frame_state* state, int32_t base) {
  for (size_t i = 0; i < sizeof(state->values) / sizeof(state->values[0]); ++i) {
    state->values[i] = base + (int32_t) (i * 3);
  }
}

static int32_t scramble_frame(struct frame_state* state, int depth) {
  int32_t total = 0;
  for (size_t i = 0; i < sizeof(state->values) / sizeof(state->values[0]); ++i) {
    int32_t v = state->values[i] ^ (int32_t) (depth * 11 + (int) i);
    state->values[i] = (v << 1) | (v >> 7);
    total += state->values[i];
  }
  return total;
}

static int32_t walk_frames(struct frame_state* state, int depth, int toggle) {
  if (depth == 0) {
    return scramble_frame(state, toggle);
  }

  int32_t subtotal = walk_frames(state, depth - 1, toggle ^ depth);
  subtotal += scramble_frame(state, depth);

  switch ((toggle + depth) % 3) {
  case 0:
    subtotal ^= state->values[depth % 8];
    break;
  case 1:
    subtotal += (state->values[(depth + 5) % 8] << 2);
    break;
  default:
    subtotal -= (state->values[(depth + 2) % 8] >> 1);
    break;
  }

  if ((toggle & depth) == 0 && depth > 1) {
    subtotal += walk_frames(state, depth - 2, toggle + depth);
  }

  return subtotal;
}

static void mix_history(int32_t history[6], int32_t value) {
  for (int i = 5; i > 0; --i) {
    history[i] = history[i - 1];
  }
  history[0] = value;
}

int main(void) {
  struct frame_state root;
  int32_t history[6] = {0};

  seed_frame(&root, 42);

  for (int round = 0; round < 5; ++round) {
    int32_t result = walk_frames(&root, 3, round);
    mix_history(history, result);
    root.values[round % 8] ^= result;
    root.values[(round + 3) % 8] ^= (result << 1);
  }

  int32_t final = 0;
  for (size_t i = 0; i < sizeof(history) / sizeof(history[0]); ++i) {
    final ^= history[i];
  }

  printf("final=%d history0=%d history1=%d\n", final, history[0], history[1]);
  return final & 0xFF;
}
