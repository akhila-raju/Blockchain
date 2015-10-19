#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ec.h>

#include "block.h"
#include "common.h"
#include "transaction.h"

/* Usage: ./balances *.blk
 * Reads in a list of block files and outputs a table of public key hashes and
 * their balance in the longest chain of blocks. In case there is more than one
 * chain of the longest length, chooses one arbitrarily. */

/* If a block has height 0, it must have this specific hash. */
const hash_output GENESIS_BLOCK_HASH = {
	0x00, 0x00, 0x00, 0x0e, 0x5a, 0xc9, 0x8c, 0x78, 0x98, 0x00, 0x70, 0x2a, 0xd2, 0xa6, 0xf3, 0xca,
	0x51, 0x0d, 0x40, 0x9d, 0x6c, 0xca, 0x89, 0x2e, 0xd1, 0xc7, 0x51, 0x98, 0xe0, 0x4b, 0xde, 0xec,
};

struct blockchain_node {
	struct blockchain_node *parent;
	struct block b;
	int is_valid;
};

/* A simple linked list to keep track of account balances. */
struct balance {
	struct ecdsa_pubkey pubkey;
	int balance;
	struct balance *next;
};

/* Add or subtract an amount from a linked list of balances. Call it like this:
 *   struct balance *balances = NULL;
 *
 *   // reward_tx increment.
 *   balances = balance_add(balances, &b.reward_tx.dest_pubkey, 1);
 *
 *   // normal_tx increment and decrement.
 *   balances = balance_add(balances, &b.normal_tx.dest_pubkey, 1);
 *   balances = balance_add(balances, &prev_transaction.dest_pubkey, -1);
 */
static struct balance *balance_add(struct balance *balances,
	struct ecdsa_pubkey *pubkey, int amount)
{
	struct balance *p;

	for (p = balances; p != NULL; p = p->next) {
		if ((byte32_cmp(p->pubkey.x, pubkey->x) == 0)
			&& (byte32_cmp(p->pubkey.y, pubkey->y) == 0)) {
			p->balance += amount;
			return balances;
		}
	}

	/* Not found; create a new list element. */
	p = malloc(sizeof(struct balance));
	if (p == NULL)
		return NULL;
	p->pubkey = *pubkey;
	p->balance = amount;
	p->next = balances;

	return p;
}

int main(int argc, char *argv[])
{
	int i;

	/* Read input block files. */
	for (i = 1; i < argc; i++) {
		char *filename;
		struct block b;
		int rc;

		filename = argv[i];
		rc = block_read_filename(&b, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}

		/* TODO */
		/* Check the singleton conditions */

		// Compute hash
		bool valid = true;
		hash_output curr_hash;
		curr_hash = block_hash(b, h);

		// If the block has height 0 (the “genesis block”), its SHA256 hash must be the hardcoded value 0000000e5ac98c789800702ad2a6f3ca510d409d6cca892ed1c75198e04bdeec. (Use the byte32_cmp function.)
		if (b->height == 0) {
			if (byte32_cmp(curr_hash, GENESIS_BLOCK_HASH) == 1) { 
				valid = valid & true; // block is valid
			} else {  
				valid = valid & false; // block is invalid
			}
		}

		// • The hash of the block must be smaller than TARGET_HASH; i.e., it must start with 24 zero bits. (Use the hash_output_is_below_target function.)
		if (hash_output_is_below_target(h) == 1) {
			valid = valid & true; // block is valid
		} else {
			valid = valid & false; // block is invalid
		}

		// • The height of both of the block's transactions must be equal to the block's height.
		if (b->reward_tx.height == b->height && b->normal_tx.height == b->height) {
			valid = valid & true; // block is valid
		} else {
			valid = valid & false; // block is invalid			
		}

		// add to list of valid blocks
		if (valid) {
			// add to list of valid blocks
		}
	}

	/* Organize into a tree, check validity, and output balances. */
	/* TODO */

	// sort list of valid blocks

	for (i = 1; i < argc; i++) {
		char *filename;
		struct block b;
		int rc;

		filename = argv[i];
		rc = block_read_filename(&b, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}

		if 

	}

// validity
// If a block has height ≥1, its parent must be a valid block with a height that is 1 smaller.
// reward_tx.prev_transaction_hash, reward_tx.src_signature.r, and reward_tx.src_signature.s members must be zero—reward transactions are not signed and do not come from another public key. (Use the byte32_zero function.)

	struct balance *balances = NULL, *p, *next;
	/* Print out the list of balances. */
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	return 0;
}
