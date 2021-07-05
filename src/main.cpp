
#include <assert.h>
#include <conio.h>
#include <stdint.h>
#include <stdio.h>

#include <chrono>
#include <filesystem>
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

class Blockchain
{
public:
	Blockchain()
	{
		// genesis block
		blocks_.emplace_back();
	}

	void mineNextBlock(uint8_t currentDifficulty);
	void save(const char* fileName) const
	{
		FILE* f = fopen(fileName, "wb");
		const uint64_t numBlocks = blocks_.size();
		fwrite(&numBlocks, sizeof(numBlocks), 1, f);
		fwrite(blocks_.data(), sizeof(Block), numBlocks, f);
		fclose(f);
	}
	void load(const char* fileName)
	{
		FILE* f = fopen(fileName, "rb");
		uint64_t numBlocks = 0;
		fread(&numBlocks, sizeof(numBlocks), 1, f);
		blocks_.resize(numBlocks);
		fread(blocks_.data(), sizeof(Block), numBlocks, f);
		fclose(f);
	}

public:
	std::vector<Block> blocks_;
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
		auto now = std::chrono::system_clock::now();
		block.timeStamp_ = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
		if (checkDifficulty(block, currentDifficulty))
		{
			calculateHash(block);
			return true;
		}
		block.nonce_++;
	}
	return false;
}

std::tm* gettm(uint64_t timestamp)
{
	auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(std::chrono::milliseconds(timestamp));
	auto tt = std::chrono::system_clock::to_time_t(tp);
	return std::gmtime(&tt);
}

/// print Block info with truncated SHAs to fit them on a single line
void printBlockNeat(const Block& block)
{
	std::tm* t = gettm(block.timeStamp_);

	printf("Metadata    : %u\n", block.metaData_);
	printf("Nonce       : %llu\n", block.nonce_);
	printf("Timestamp   : %llu (%4d/%02d/%02d %02d:%02d:%02d +0000 GMT)\n", block.timeStamp_, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	printf("Prev SHA-512: %.64s\n", block.hashPrev_);
	printf("SHA-512     : %.64s\n", block.hash_);
	printf("PayloadSz   : %u\n\n", (uint32_t)block.payloadSize_);
}

void Blockchain::mineNextBlock(uint8_t currentDifficulty)
{
	Block block;
	memcpy(block.hashPrev_, blocks_.back().hash_, SHA512_DIGEST_STRING_LENGTH);
	mineBlock(block, currentDifficulty);
	printBlockNeat(block);
	blocks_.push_back(block);
}

int main()
{
	const uint8_t currentDifficulty = 4;
	const char* blockchainFile = "tiny-blockchain.data";

	Blockchain chain;
	if (std::filesystem::exists(blockchainFile))
		chain.load(blockchainFile);

	printf("Mining... (press ESC to abort)\n\n");

	while (!_kbhit())
	{
		chain.mineNextBlock(currentDifficulty);
		chain.save(blockchainFile);
	}
	return 0;
}
