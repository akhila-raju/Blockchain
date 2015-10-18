#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/objects.h>

#include "common.h"

/* Mined blocks must have a hash less than this in order to be considered
 * valid; i.e., it must start with at least a certain number of zero bits. */
const hash_output TARGET_HASH = {
	0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* This is the elliptic curve group we use for everything. */
const int EC_GROUP_NID = NID_secp256k1;

/* Store a big-endian representation of n in buf. */
void serialize_uint32(unsigned char buf[4], uint32_t n)
{
	buf[0] = (n & 0xff000000UL) >> 24;
	buf[1] = (n & 0x00ff0000UL) >> 16;
	buf[2] = (n & 0x0000ff00UL) >> 8;
	buf[3] = (n & 0x000000ffUL);
}

/* Deserialize and return a uint32_t. */
uint32_t deserialize_uint32(const unsigned char buf[4])
{
	return (((uint32_t) buf[0]) << 24)
		| (((uint32_t) buf[1]) << 16)
		| (((uint32_t) buf[2]) << 8)
		| ((uint32_t) buf[3]);
}

/* Compare two byte arrays. Returns -1, 0, +1 like strcmp. */
int byte32_cmp(const unsigned char a[32], const unsigned char b[32])
{
	unsigned int i;

	for (i = 0; i < 32; i++) {
		if (a[i] < b[i])
			return -1;
		if (a[i] > b[i])
			return 1;
	}

	return 0;
}

/* Return 1 if b is all zeros; 0 otherwise. */
int byte32_is_zero(const unsigned char b[32])
{
	unsigned int i;

	for (i = 0; i < 32; i++) {
		if (b[i] != 0)
			return 0;
	}

	return 1;
}

/* Convert an unsigned int[32] array to a hex string. The string is statically
 * allocated and will be overwritten at the next call to this function. */
const char *byte32_to_hex(const unsigned char b[32])
{
	static char s[2*32+1];
	int n;

	n = snprintf(s, sizeof(s),
		"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
		b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23],
		b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]);
	if (n + 1 != sizeof(s))
		abort();

	return s;
}

/* Return 1 if h is less than or equal to TARGET_HASH; 0 otherwise. */
int hash_output_is_below_target(const hash_output h)
{
	return byte32_cmp(h, TARGET_HASH) <= 0;
}

/* Read an EC private key from a file pointer. Returns NULL on error. */
EC_KEY *key_read(FILE *fp)
{
	unsigned char buf[1024];
	const unsigned char *p;
	EC_KEY *key;
	int n;

	n = fread(buf, 1, sizeof(buf), fp);
	if (ferror(fp) != 0)
		return NULL;

	p = buf;
	key = d2i_ECPrivateKey(NULL, &p, n);
	if (key == NULL)
		return NULL;

	return key;
}

/* Read an EC private key from a named file. Returns NULL on error. */
EC_KEY *key_read_filename(const char *filename)
{
	FILE *fp;
	int rc;
	EC_KEY *key;

	fp = fopen(filename, "rb");
	if (fp == NULL)
		return 0;
	key = key_read(fp);
	if (key == NULL) {
		fclose(fp);
		return NULL;
	}
	rc = fclose(fp);
	if (rc != 0) {
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}

/* Write an EC private key to a file pointer. Returns 1 for success, 0 for
 * error. */
int key_write(FILE *fp, EC_KEY *key)
{
	unsigned char *buf;
	int n;

	/* Don't encode the public key. The public key will be computed
	 * automatically when the file is loaded again. */
	EC_KEY_set_enc_flags(key, EC_PKEY_NO_PUBKEY);

	buf = NULL;
	n = i2d_ECPrivateKey(key, &buf);
	if (n < 0) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (fwrite(buf, n, 1, fp) != 1)
		return 0;

	OPENSSL_free(buf);

	return 1;
}

/* Write an EC private key to a named file. Returns 1 for success, 0 for
 * error. */
int key_write_filename(const char *filename, EC_KEY *key)
{
	FILE *fp;
	int rc;

	fp = fopen(filename, "wb");
	if (fp == NULL)
		return 0;
	rc = key_write(fp, key);
	if (!rc) {
		fclose(fp);
		return rc;
	}

	return fclose(fp) == 0;
}
