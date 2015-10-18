#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>

#include "block.h"
#include "common.h"

/* The size of a block in bytes (e.g. when prepared for hashing or writing to a
 * file). We don't just take sizeof(struct block) because there may be
 * padding inside the structure. */
static const size_t SERIALIZED_BLOCK_LEN =
	/* prev_block_hash */
	sizeof(hash_output) +
	/* height, nonce */
	4 + 4 +
	/* reward_tx */
	4 + sizeof(hash_output) +
	32 + 32 + 32 + 32 +
	/* normal_tx */
	4 + sizeof(hash_output) +
	32 + 32 + 32 + 32;

static void serialize(unsigned char **p, const unsigned char *endp,
	const unsigned char *buf, size_t len)
{
	if (*p + len > endp)
		abort();
	memmove(*p, buf, len);
	*p += len;
}

static void deserialize(const unsigned char **p, const unsigned char *endp,
	unsigned char *buf, size_t len)
{
	if (*p + len > endp)
		abort();
	memmove(buf, *p, len);
	*p += len;
}

/* Serialize a block into a flat array (for hashing or writing to a file). */
static void block_serialize(const struct block *b, unsigned char buf[SERIALIZED_BLOCK_LEN])
{
	unsigned char *p, *endp;
	unsigned char uint32_buf[4];

	p = buf;
	endp = buf + SERIALIZED_BLOCK_LEN;
	serialize(&p, endp, b->prev_block_hash, sizeof(b->prev_block_hash));
	serialize_uint32(uint32_buf, b->height);
	serialize(&p, endp, uint32_buf, sizeof(uint32_buf));
	serialize_uint32(uint32_buf, b->nonce);
	serialize(&p, endp, uint32_buf, sizeof(uint32_buf));
	serialize_uint32(uint32_buf, b->reward_tx.height);
	serialize(&p, endp, uint32_buf, sizeof(uint32_buf));
	serialize(&p, endp, b->reward_tx.prev_transaction_hash, sizeof(b->reward_tx.prev_transaction_hash));
	serialize(&p, endp, b->reward_tx.dest_pubkey.x, sizeof(b->reward_tx.dest_pubkey.x));
	serialize(&p, endp, b->reward_tx.dest_pubkey.y, sizeof(b->reward_tx.dest_pubkey.y));
	serialize(&p, endp, b->reward_tx.src_signature.r, sizeof(b->reward_tx.src_signature.r));
	serialize(&p, endp, b->reward_tx.src_signature.s, sizeof(b->reward_tx.src_signature.s));
	serialize_uint32(uint32_buf, b->normal_tx.height);
	serialize(&p, endp, uint32_buf, sizeof(uint32_buf));
	serialize(&p, endp, b->normal_tx.prev_transaction_hash, sizeof(b->normal_tx.prev_transaction_hash));
	serialize(&p, endp, b->normal_tx.dest_pubkey.x, sizeof(b->normal_tx.dest_pubkey.x));
	serialize(&p, endp, b->normal_tx.dest_pubkey.y, sizeof(b->normal_tx.dest_pubkey.y));
	serialize(&p, endp, b->normal_tx.src_signature.r, sizeof(b->normal_tx.src_signature.r));
	serialize(&p, endp, b->normal_tx.src_signature.s, sizeof(b->normal_tx.src_signature.s));
	if (p != endp)
		abort();
}

/* Deserialize a block structure from a flat array. */
static void block_deserialize(struct block *b, unsigned char buf[SERIALIZED_BLOCK_LEN])
{
	const unsigned char *p, *endp;
	unsigned char uint32_buf[4];

	p = buf;
	endp = buf + SERIALIZED_BLOCK_LEN;
	deserialize(&p, endp, b->prev_block_hash, sizeof(b->prev_block_hash));
	deserialize(&p, endp, uint32_buf, sizeof(uint32_buf));
	b->height = deserialize_uint32(uint32_buf);
	deserialize(&p, endp, uint32_buf, sizeof(uint32_buf));
	b->nonce = deserialize_uint32(uint32_buf);
	deserialize(&p, endp, uint32_buf, sizeof(uint32_buf));
	b->reward_tx.height = deserialize_uint32(uint32_buf);
	deserialize(&p, endp, b->reward_tx.prev_transaction_hash, sizeof(b->reward_tx.prev_transaction_hash));
	deserialize(&p, endp, b->reward_tx.dest_pubkey.x, sizeof(b->reward_tx.dest_pubkey.x));
	deserialize(&p, endp, b->reward_tx.dest_pubkey.y, sizeof(b->reward_tx.dest_pubkey.y));
	deserialize(&p, endp, b->reward_tx.src_signature.r, sizeof(b->reward_tx.src_signature.r));
	deserialize(&p, endp, b->reward_tx.src_signature.s, sizeof(b->reward_tx.src_signature.s));
	deserialize(&p, endp, uint32_buf, sizeof(uint32_buf));
	b->normal_tx.height = deserialize_uint32(uint32_buf);
	deserialize(&p, endp, b->normal_tx.prev_transaction_hash, sizeof(b->normal_tx.prev_transaction_hash));
	deserialize(&p, endp, b->normal_tx.dest_pubkey.x, sizeof(b->normal_tx.dest_pubkey.x));
	deserialize(&p, endp, b->normal_tx.dest_pubkey.y, sizeof(b->normal_tx.dest_pubkey.y));
	deserialize(&p, endp, b->normal_tx.src_signature.r, sizeof(b->normal_tx.src_signature.r));
	deserialize(&p, endp, b->normal_tx.src_signature.s, sizeof(b->normal_tx.src_signature.s));
	if (p != endp)
		abort();
}

/* Initialize a block with the given parent. If parent==NULL, then the block has
 * no parent; i.e., it is a genesis block. */
void block_init(struct block *b, const struct block *parent)
{
	memset(b, 0, sizeof(*b));

	if (parent == NULL) {
		/* This is a genesis block. */
		return;
	}

	block_hash(parent, b->prev_block_hash);
	b->height = parent->height + 1;
	b->reward_tx.height = b->height;
	b->normal_tx.height = b->height;
}

/* Compute the hash value of a block using the current nonce. */
void block_hash(const struct block *b, hash_output h)
{
	unsigned char buf[SERIALIZED_BLOCK_LEN];
	SHA256_CTX sha;

	block_serialize(b, buf);

	SHA256_Init(&sha);
	SHA256_Update(&sha, buf, sizeof(buf));
	SHA256_Final(h, &sha);
}

/* Mine a block. Increment the nonce until the block's hash output satisfies
 * TARGET_HASH. */
void block_mine(struct block *b)
{
	/* TODO */
}

/* Print a human-readable representation of the block to fp. */
void block_print(const struct block *b, FILE *fp)
{
	hash_output h;

	block_hash(b, h);
	fprintf(fp, "== BLOCK %s ==\n", byte32_to_hex(h));
	fprintf(fp, "prev_block_hash: %s\n", byte32_to_hex(b->prev_block_hash));
	fprintf(fp, "height: %lu\n", (unsigned long) b->height);
	fprintf(fp, "nonce: 0x%016lx\n", (unsigned long) b->nonce);

	transaction_hash(&b->reward_tx, h);
	fprintf(fp, "  == REWARD TX %s ==\n", byte32_to_hex(h));
	fprintf(fp, "  prev_transaction_hash: %s\n", byte32_to_hex(b->reward_tx.prev_transaction_hash));
	fprintf(fp, "  dest_pubkey.x: %s\n", byte32_to_hex(b->reward_tx.dest_pubkey.x));
	fprintf(fp, "  dest_pubkey.y: %s\n", byte32_to_hex(b->reward_tx.dest_pubkey.y));
	fprintf(fp, "  src_signature.r: %s\n", byte32_to_hex(b->reward_tx.src_signature.r));
	fprintf(fp, "  src_signature.s: %s\n", byte32_to_hex(b->reward_tx.src_signature.s));

	transaction_hash(&b->normal_tx, h);
	fprintf(fp, "  == NORMAL TX %s ==\n", byte32_to_hex(h));
	fprintf(fp, "  prev_transaction_hash: %s\n", byte32_to_hex(b->normal_tx.prev_transaction_hash));
	fprintf(fp, "  dest_pubkey.x: %s\n", byte32_to_hex(b->normal_tx.dest_pubkey.x));
	fprintf(fp, "  dest_pubkey.y: %s\n", byte32_to_hex(b->normal_tx.dest_pubkey.y));
	fprintf(fp, "  src_signature.r: %s\n", byte32_to_hex(b->normal_tx.src_signature.r));
	fprintf(fp, "  src_signature.s: %s\n", byte32_to_hex(b->normal_tx.src_signature.s));
}

/* Read a block from a file pointer. Returns 1 for success; 0 for failure. */
int block_read(struct block *b, FILE *fp)
{
	unsigned char buf[SERIALIZED_BLOCK_LEN];
	int n;

	n = fread(buf, sizeof(buf), 1, fp);
	if (n != 1)
		return 0;
	block_deserialize(b, buf);

	return 1;
}

/* Read a block from a named file. Returns 1 for success; 0 for failure. */
int block_read_filename(struct block *b, const char *filename)
{
	FILE *fp;
	int rc;

	fp = fopen(filename, "rb");
	if (fp == NULL)
		return 0;
	rc = block_read(b, fp);
	if (rc != 1) {
		fclose(fp);
		return rc;
	}
	rc = fclose(fp);

	return rc == 0;
}

/* Write a block to a file pointer. Returns 1 for success; 0 for failure. */
int block_write(const struct block *b, FILE *fp)
{
	unsigned char buf[SERIALIZED_BLOCK_LEN];
	int n;

	block_serialize(b, buf);
	n = fwrite(buf, sizeof(buf), 1, fp);

	return n >= 0;
}

/* Write a block to a named file. Returns 1 for success; 0 for failure. */
int block_write_filename(const struct block *b, const char *filename)
{
	FILE *fp;
	int rc;

	fp = fopen(filename, "wb");
	if (fp == NULL)
		return 0;
	rc = block_write(b, fp);
	if (rc != 1) {
		fclose(fp);
		return rc;
	}
	rc = fclose(fp);

	return rc == 0;
}
