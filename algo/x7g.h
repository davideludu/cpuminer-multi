#ifndef X7G_H
#define X7G_H

#include <stdint.h>
#include <stddef.h>  // For NULL
#include <string.h>  // For memory functions
#include "miner.h"   // Include the header file where `struct work` is defined
#include <openssl/sha.h>

// Function to get the block timestamp from the work structure
uint32_t getBlockTimestamp(const struct work *work);

#include <stdint.h>


// Function to perform SHA256 hashing
void sha256(const unsigned char *data, size_t len, unsigned char *hash);

// Function to generate a unique ID for the block header
void GenerateUniqueID(uint32_t version, const unsigned char *prevhash, uint32_t curtime, uint32_t bits, unsigned char *uniqueID);

// Function to print the unique ID in hexadecimal format
void PrintUniqueID(const unsigned char *uniqueID);
#endif // X7G_H
