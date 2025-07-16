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

/**
 * @file expand_matrix.c
 * @brief Helper utility to expand and save the public key matrix A to a file.
 *
 * This program loads a public key from "pk.bin", expands the matrix A from
 * the public key's rho parameter using the polyvec_matrix_expand function,
 * converts the matrix polynomials from the NTT domain back to the integer
 * domain, and saves the coefficients of the matrix polynomials to "pk.mat",
 * with each coefficient on a new line.
 */

#include <omp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packing.h"
#include "poly.h"

int main(void) {
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];

  /* Load keys */
  {
    FILE* pk_file = fopen("pk.bin", "r");
    if (pk_file == NULL) {
      fprintf(stderr, "Failed to open pk.bin\n");
      exit(-1);
    }
    size_t pk_read = fread(pk, 1, sizeof(pk), pk_file);
    if (pk_read != sizeof(pk)) {
      fprintf(stderr, "Failed to read keys from file\n");
      exit(-1);
    }
    fclose(pk_file);
  }

  FILE* mat_file = fopen("pk.mat", "w");
  if (mat_file == NULL) {
    fprintf(stderr, "Failed to open pk.mat\n");
    exit(-1);
  }

  {
    uint8_t* rho = pk;
    polyvecl mat[K];

    // One in NTT domain.
    poly one_ntt;
    memset(&one_ntt, 0, sizeof(one_ntt));
    one_ntt.coeffs[0] = 1;
    poly_ntt(&one_ntt);

    // Expand matrix from seed.
    polyvec_matrix_expand(mat, rho);

    // Convert matrix back to integer domain.
    for (int i = 0; i < K; i++) {
      for (int j = 0; j < L; j++) {
        poly mont;
        poly_pointwise_montgomery(&mont, &one_ntt, &mat[i].vec[j]);
        poly_invntt_tomont(&mont);
        for (int k = 0; k < N; k++) {
          fprintf(mat_file, "%d\n", mont.coeffs[k]);
        }
      }
    }
  }

  return 0;
}
