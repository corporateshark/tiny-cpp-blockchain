
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <vector>

#include "sha2.h"

#if _MSC_VER
#	pragma warning(disable:4200) // nonstandard extension used: zero-sized array in struct/union
#endif // _MSC_VER

struct Block
{
	uint32_t metaData_ = 0;
	uint64_t nonce_ = 0;
	uint64_t timeStamp_ = 0; // milliseconds
	char hashPrev_[SHA512_DIGEST_STRING_LENGTH] = { 0 };
	char hash_[SHA512_DIGEST_STRING_LENGTH] = { 0 };
	uint16_t payloadSize_ = 0;
	uint8_t payload_[];
};

void calculateHash(Block& block)
{
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, (const uint8_t*)&block, sizeof(Block) + block.payloadSize_);
	SHA512_End(&ctx, block.hash_);
}

bool checkDifficulty(const Block& block, uint8_t difficulty)
{
	assert(difficulty < SHA512_DIGEST_STRING_LENGTH);

	SHA512_CTX ctx;

	char hash[SHA512_DIGEST_STRING_LENGTH] = { 0 };

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, (const uint8_t*)&block, sizeof(Block) + block.payloadSize_);
	SHA512_End(&ctx, hash);

	for (uint8_t i = 0; i != difficulty; i++)
		if (hash[i] != '0') return false;

	return true;
}

bool mineBlock(Block& block, uint8_t currentDifficulty)
{
	for (;;)
	{
		if (checkDifficulty(block, currentDifficulty))
		{
			calculateHash(block);
			return true;
		}
		block.nonce_++;
	}
	return false;
}

/// print Block info with truncated SHAs to fit them on a single line
void printBlockNeat(const Block& block)
{
	printf("Metadata    : %u\n", block.metaData_);
	printf("Nonce       : %llu\n", block.nonce_);
	printf("Timestamp   : %llu\n", block.timeStamp_);
	printf("Prev SHA-512: %.64s\n", block.hashPrev_);
	printf("SHA-512     : %.64s\n", block.hash_);
	printf("PayloadSz   : %u\n\n", (uint32_t)block.payloadSize_);
}

int main()
{
	printf("Mining...\n\n");

	Block block;

	mineBlock(block, 5);
	printBlockNeat(block);

	return 0;
}
