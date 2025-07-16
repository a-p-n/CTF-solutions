/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <omp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "fips202.h"
#include "sign.h"

#define CTXLEN 14
#define NUM_SIG 100000
#define SK_SEEDBYTES (SEEDBYTES * 2 + TRBYTES)

const char ctx[] = "gctf_dilithium";

int main(void) {
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  /* Prepare dilithium key */
  FILE* pk_file = fopen("pk.bin", "r");
  FILE* sk_file = fopen("../private/sk.bin", "r");
  if (pk_file == NULL || sk_file == NULL) {
    fprintf(stderr, "Generate keys\n");
    assert(sk_file == NULL);
    crypto_sign_keypair(pk, sk);
    pk_file = fopen("pk.bin", "w");
    sk_file = fopen("../private/sk.bin", "w");
    fwrite(pk, 1, sizeof(pk), pk_file);
    fwrite(sk, 1, sizeof(sk), sk_file);
  } else {
    fprintf(stderr, "Loading keys\n");
    size_t pk_read = fread(pk, 1, sizeof(pk), pk_file);
    size_t sk_read = fread(sk, 1, sizeof(sk), sk_file);
    if (pk_read != sizeof(pk) || sk_read != sizeof(sk)) {
      fprintf(stderr, "Failed to read keys from file\n");
      exit(-1);
    }
  }
  fclose(pk_file);
  fclose(sk_file);

  fprintf(stderr, "Generate signatures\n");
  FILE* sig_file = fopen("sig.bin", "w");
  size_t completed = 0;

  #pragma omp parallel for
  for (uint32_t m = 0; m < NUM_SIG; ++m) {
    uint8_t sm[CRYPTO_BYTES];
    size_t smlen;

    crypto_sign_signature(sm, &smlen, (uint8_t*)&m, sizeof(m),
                          ctx, sizeof(ctx), sk);

    int failed = crypto_sign_verify(sm, smlen, (uint8_t*)&m, sizeof(m),
                                    ctx, sizeof(ctx), pk);
    if (failed || smlen != CRYPTO_BYTES) {
      fprintf(stderr, "Sanity check failed\n");
      exit(-1);
    }

    #pragma omp critical
    {
      if (fwrite(sm, 1, smlen, sig_file) != smlen) {
        fprintf(stderr, "Failed to write signature to file\n");
        exit(-1);
      }
      completed += 1;
      if ((completed + 1) % (NUM_SIG / 1000) == 0) {
        printf("\rProgress: %3d", (completed + 1) * 100 / NUM_SIG);
        fflush(stdout);
      }
    }
  }
  printf("\n");

  fprintf(stderr, "Encrypt flag with secrets\n");
  {
    // Gather secrets: s1, s2, t0
    uint8_t sk_hash[256];
    shake256(sk_hash, sizeof(sk_hash),
             sk + SK_SEEDBYTES,             // Skip seeds
             L * POLYETA_PACKEDBYTES +      // s1
                 K * POLYETA_PACKEDBYTES +  // s2
                 K * POLYT0_PACKEDBYTES     // t0
    );

    // PoW
    for (size_t i = 0; i < (1 << 20); i++) {
      shake256(sk_hash, sizeof(sk_hash), sk_hash, sizeof(sk_hash));
    }

    // Encrypt flag with xor
    FILE* flag_file = fopen("../flag.txt", "r");
    if (flag_file == NULL) {
      fprintf(stderr, "Failed to open flag.txt\n");
      exit(-1);
    }
    uint8_t flag[256];
    size_t flag_size = fread(flag, 1, sizeof(flag), flag_file);
    fclose(flag_file);
    for (size_t i = 0; i < flag_size; i++) {
      flag[i] ^= sk_hash[i];
    }

    // Save encrypted flag
    FILE* enc_flag_file = fopen("flag.enc", "w");
    if (enc_flag_file == NULL) {
      fprintf(stderr, "Failed to open flag.enc\n");
      exit(-1);
    }
    fwrite(flag, 1, flag_size, enc_flag_file);
    fclose(enc_flag_file);
  }

  return 0;
}
