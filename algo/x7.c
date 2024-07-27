#include "miner.h"
#include "x7g.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"

#define HEADER_SIZE 80

void x7hash(void *output, const void *input, uint64_t timestamp)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_keccak512_context    ctx_keccak;
    sph_luffa512_context     ctx_luffa1;
    sph_simd512_context      ctx_simd1;
    sph_echo512_context      ctx_echo1;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t _ALIGN(64) hashA[16], hashB[16];

    // Prepare the extended input which includes the timestamp
    unsigned char extended_input[80];
    memcpy(extended_input, input, 64); // Copy original input
    memcpy(extended_input + 64, &timestamp, sizeof(timestamp)); // Append timestamp

    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, extended_input, sizeof(extended_input));
    sph_blake512_close(&ctx_blake, hashA);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    // XOR the result of BMW with Blake
    for (int i = 0; i < 16; ++i) {
        hashB[i] ^= hashA[i];
    }

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hashA);

    // XOR the result of Groestl with BMW
    for (int i = 0; i < 16; ++i) {
        hashA[i] ^= hashB[i];
    }

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hashA, 64);
    sph_keccak512_close(&ctx_keccak, hashB);

    // XOR the result of Keccak with Groestl
    for (int i = 0; i < 16; ++i) {
        hashB[i] ^= hashA[i];
    }

    sph_luffa512_init(&ctx_luffa1);
    sph_luffa512(&ctx_luffa1, hashB, 64);
    sph_luffa512_close(&ctx_luffa1, hashA);

    // XOR the result of Luffa with Keccak
    for (int i = 0; i < 16; ++i) {
        hashA[i] ^= hashB[i];
    }

    sph_echo512_init(&ctx_echo1);
    sph_echo512(&ctx_echo1, hashA, 64);
    sph_echo512_close(&ctx_echo1, hashB);

    // XOR the result of Echo with Luffa
    for (int i = 0; i < 16; ++i) {
        hashB[i] ^= hashA[i];
    }

    memcpy(output, hashB, 32);
}


int scanhash_x7(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done) {
    uint32_t _ALIGN(128) hash[8];
    uint32_t _ALIGN(128) endiandata[20];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    struct BlockHeader *header = &work->header; // Access block header from work

    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t nonce = first_nonce;
    volatile uint8_t *restart = &(work_restart[thr_id].restart);

    if (opt_benchmark) {
        ptarget[7] = 0x0cff;
    }

    // Convert data to little-endian format
    for (int k = 0; k < 19; k++) {
        be32enc(&endiandata[k], pdata[k]);
    }

    do {
        be32enc(&endiandata[19], nonce);

        // Prepare the data for hashing: Serialize block header
        unsigned char header_data[HEADER_SIZE] = {0};

        // Serialize the block header into header_data array
        size_t offset = 0;
        memcpy(header_data + offset, &header->nVersion, sizeof(header->nVersion));
        offset += sizeof(header->nVersion);
        memcpy(header_data + offset, &header->hashPrevBlock, sizeof(header->hashPrevBlock));
        offset += sizeof(header->hashPrevBlock);
        memcpy(header_data + offset, &header->hashMerkleRoot, sizeof(header->hashMerkleRoot));
        offset += sizeof(header->hashMerkleRoot);
        memcpy(header_data + offset, &header->nTime, sizeof(header->nTime));
        offset += sizeof(header->nTime);
        memcpy(header_data + offset, &header->nBits, sizeof(header->nBits));
        offset += sizeof(header->nBits);
        memcpy(header_data + offset, &nonce, sizeof(nonce));

        // Convert header_data to uint32_t array for x7hash
        uint32_t header_uint32[HEADER_SIZE / 4];
        memcpy(header_uint32, header_data, HEADER_SIZE);

        // Retrieve the block timestamp from the work structure
        uint64_t current_timestamp = getBlockTimestamp(work);

        // Apply the X7 hash function with XOR operations
        x7hash(hash, header_uint32, current_timestamp);

        // Check if the hash meets the target
        if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
            work_set_target_ratio(work, hash);
            pdata[19] = nonce;
            *hashes_done = pdata[19] - first_nonce;
            return 1;
        }
        nonce++;

    } while (nonce < max_nonce && !(*restart));

    pdata[19] = nonce;
    *hashes_done = pdata[19] - first_nonce + 1;
    return 0;
}

void sha256(const unsigned char *data, size_t len, unsigned char *hash)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);
}

// Function to generate a unique ID for the block header
void GenerateUniqueID(uint32_t version, const unsigned char *prevhash, uint32_t curtime, uint32_t bits, unsigned char *uniqueID)
{
    unsigned char header[HEADER_SIZE] = {0};
    size_t offset = 0;

    // Assemble block header data
    memcpy(header + offset, &version, sizeof(version));
    offset += sizeof(version);

    memcpy(header + offset, prevhash, 32);
    offset += 32;

    memcpy(header + offset, &curtime, sizeof(curtime));
    offset += sizeof(curtime);

    memcpy(header + offset, &bits, sizeof(bits));
    offset += sizeof(bits);

    // Zero out the rest of the header if needed
    memset(header + offset, 0, HEADER_SIZE - offset);

    // Generate the unique ID by hashing the header
    sha256(header, HEADER_SIZE, uniqueID);
}

// Function to print the unique ID in hexadecimal format
void PrintUniqueID(const unsigned char *uniqueID)
{
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", uniqueID[i]);
    printf("\n");
}
