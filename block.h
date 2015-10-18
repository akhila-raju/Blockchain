#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <stdio.h>

#include "common.h"
#include "transaction.h"

/* A block is one mining output. It contains one or two transactions: a reward
 * transaction (paid to the miner's public key) and an optional normal
 * transaction (paid from one public key to any other). The reward transaction
 * must have all zeros as its prev_transaction_hash and src_signature. The
 * normal transaction, if unused, must have all zeros as its
 * prev_transaction_hash, dest_pubkey_hash, and src_signature.
 *
 * height is the height of this block in the blockchain. The root of the
 * blockchain (the "genesis block") must have height==0 and prev_block_hash all
 * zeros.
 *
 * nonce is the value that is tweaked until the hash of the block satisfies
 * TARGET_HASH. */
struct block {
	hash_output prev_block_hash;
	uint32_t height;
	uint32_t nonce;
	struct transaction reward_tx;
	struct transaction normal_tx;
};

void block_init(struct block *b, const struct block *parent);

void block_hash(const struct block *b, hash_output h);

void block_mine(struct block *b);

void block_print(const struct block *b, FILE *fp);

int block_read(struct block *b, FILE *fp);

int block_read_filename(struct block *b, const char *filename);

int block_write(const struct block *b, FILE *fp);

int block_write_filename(const struct block *b, const char *filename);

#endif
