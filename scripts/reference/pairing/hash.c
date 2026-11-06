// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
// Test-only stdin adapter to the official portable BLAKE3 C implementation.
#include <stdio.h>
#include "blake3.h"
int main(void) {
  blake3_hasher h; blake3_hasher_init(&h);
  unsigned char input[4096], output[32]; size_t count;
  while ((count = fread(input, 1, sizeof input, stdin)) != 0)
    blake3_hasher_update(&h, input, count);
  if (ferror(stdin)) return 1;
  blake3_hasher_finalize(&h, output, sizeof output);
  return fwrite(output, 1, sizeof output, stdout) == sizeof output ? 0 : 1;
}
