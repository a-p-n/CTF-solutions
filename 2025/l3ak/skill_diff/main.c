#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

uint8_t sb[256] = {238,180,132,65,223,139,245,252,68,184,227,73,30,225,253,204,
86,7,202,243,41,213,118,167,136,193,236,107,33,13,183,229,
105,55,182,94,155,109,18,119,186,52,224,221,131,83,165,110,
113,185,44,209,228,157,148,143,108,134,101,141,80,31,40,23,
210,154,244,181,22,226,97,151,251,76,102,125,45,158,240,137,
25,235,248,53,153,166,164,208,220,198,106,88,201,163,38,121,
10,82,84,173,215,161,63,24,250,57,66,4,21,1,5,43,
27,92,58,218,112,114,171,103,177,99,50,87,211,122,0,39,
138,75,46,239,2,6,91,176,178,127,237,169,133,34,231,15,
11,81,49,69,62,123,212,71,90,249,172,98,233,254,255,203,
116,8,128,200,74,145,205,187,222,59,70,16,26,207,160,217,
191,246,179,72,150,140,89,14,64,174,37,232,242,170,19,47,
216,77,9,67,104,36,135,35,147,60,247,117,129,56,175,196,
189,149,206,42,152,192,120,51,96,85,93,144,146,126,100,48,
29,32,194,130,197,162,188,61,142,95,3,159,28,124,241,190,
219,230,156,20,214,54,199,111,168,79,234,195,17,12,115,78};
uint8_t aff[16][2] = {{109,211},{123,254},{81,20},{129,182},{251,74},{57,11},{213,44},{155,52},
  {205,146},{239,12},{123,218},{143,178},{63,228},{153,223},{237,1},{133,72}};

uint8_t round_keys[4][16];

void generate_round_keys(const uint8_t master[16]) {
    memcpy(round_keys[0], master, 16);
    for (int i = 0; i < 3; i++) {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, round_keys[i], 16);
        SHA256_Update(&ctx, master, 16);
        uint8_t hash[32];
        SHA256_Final(hash, &ctx);
        memcpy(round_keys[i+1], hash, 16);
    }
}

void matrix_multiply(const uint8_t in[16], uint8_t out[16]) {
    out[0] = in[7] + in[8] + in[9] + in[14];
    out[1] = in[2] + in[10] + in[12] + in[13];
    out[2] = in[3] + in[9] + in[12];
    out[3] = in[3] + in[5] + in[11] + in[13];
    out[4] = in[5] + in[7];
    out[5] = in[4] + in[8];
    out[6] = in[0] + in[1] + in[2] + in[3] + in[4] + in[5] + in[10];
    out[7] = in[5] + in[7] + in[8] + in[9] + in[11] + in[12];
    out[8] = in[1] + in[5] + in[8] + in[10] + in[12];
    out[9] = in[0] + in[3] + in[13] + in[15];
    out[10] = in[6] + in[7] + in[9] + in[12];
    out[11] = in[4] + in[6] + in[9] + in[10] + in[15];
    out[12] = in[1] + in[7] + in[14];
    out[13] = in[0] + in[9] + in[11] + in[12] + in[13] + in[14];
    out[14] = in[0] + in[2] + in[7] + in[15];
    out[15] = in[1];
}

void encrypt_block(uint8_t block[16]) {
    for (int i = 0; i < 16; i++)
        block[i] = (block[i] + round_keys[0][i]) & 0xff;

    for (int r = 0; r < 3; r++) {
        uint8_t tmp[16];
        matrix_multiply(block, tmp);

        for (int i = 0; i < 16; i++) {
            uint8_t a = aff[i][0], b = aff[i][1];
            uint8_t v = (a * tmp[i] + b) & 0xff;
            v ^= 1;
            v = sb[v];
            block[i] = (v + round_keys[r+1][i]) & 0xff;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s keyfile infile\n", argv[0]);
        return 1;
    }

    // Read key
    FILE *key_file = fopen(argv[1], "rb");
    if (!key_file) {
        perror("Error opening key file");
        return 1;
    }

    unsigned char key[16];
    if (fread(key, 1, 16, key_file) != 16) {
        fprintf(stderr, "Error: key file must be exactly 16 bytes\n");
        fclose(key_file);
        return 1;
    }
    fclose(key_file);

    generate_round_keys(key);

    // Read whole input file
    FILE *f = fopen(argv[2], "rb");
    if (!f) {
        fprintf(stderr, "Failed to open input file %s\n", argv[2]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (filesize % 16 != 0) {
        fprintf(stderr, "File size (%ld bytes) is not a multiple of 16. Aborting.\n", filesize);
        fclose(f);
        return 1;
    }

    uint8_t *buffer = malloc(filesize);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(f);
        return 1;
    }

    if (fread(buffer, 1, filesize, f) != (size_t)filesize) {
        fprintf(stderr, "Failed to read entire file.\n");
        free(buffer);
        fclose(f);
        return 1;
    }
    fclose(f);

    // Encrypt in place
    for (long offset = 0; offset < filesize; offset += 16) {
        encrypt_block(buffer + offset);
    }

    // Write whole file back
    f = fopen(argv[2], "wb");
    if (!f) {
        fprintf(stderr, "Failed to open file for writing: %s\n", argv[2]);
        free(buffer);
        return 1;
    }

    if (fwrite(buffer, 1, filesize, f) != (size_t)filesize) {
        fprintf(stderr, "Failed to write entire file.\n");
        free(buffer);
        fclose(f);
        return 1;
    }

    free(buffer);
    fclose(f);

    return 0;
}
