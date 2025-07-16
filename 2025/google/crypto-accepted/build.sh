#!/bin/bash

# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

mkdir -p public
mkdir -p private
mkdir -p build
cd build

if [[ ! -d "better-dilithium" ]]; then
  git clone https://github.com/pq-crystals/dilithium.git "better-dilithium"
  cd "better-dilithium"
  git checkout --detach 444cdcc84eb36b66fe27b3a2529ee48f6d8150c2
  git apply ../../src/patch.diff
  cd ..
fi

cd ../public

DILITHIUM_SRCS=(
  sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c
  fips202.c symmetric-shake.c randombytes.c
)

gcc -fopenmp -O3 -DDILITHIUM_MODE=2 -o task \
  "-I../build/better-dilithium/ref/" \
  "${DILITHIUM_SRCS[@]/#/../build/better-dilithium/ref/}" \
  ../src/task.c

./task

gcc -fopenmp -O3 -DDILITHIUM_MODE=2 -o expand_matrix \
  "-I../build/better-dilithium/ref/" \
  "${DILITHIUM_SRCS[@]/#/../build/better-dilithium/ref/}" \
  ../helper/expand_matrix.c

./expand_matrix

ls -lah
