#include <string.h>

#include <openssl/ecdsa.h>
#include <openssl/sha.h>

#include "common.h"
#include "transaction.h"

/* Compute the hash value of this transaction. */
void transaction_hash(const struct transaction *tx, hash_output h)
{
	unsigned char uint32_buf[4];
	SHA256_CTX sha;

	SHA256_Init(&sha);
	serialize_uint32(uint32_buf, tx->height);
	SHA256_Update(&sha, uint32_buf, sizeof(uint32_buf));
	SHA256_Update(&sha, tx->prev_transaction_hash, sizeof(tx->prev_transaction_hash));
	SHA256_Update(&sha, tx->dest_pubkey.x, sizeof(tx->dest_pubkey.x));
	SHA256_Update(&sha, tx->dest_pubkey.y, sizeof(tx->dest_pubkey.y));
	SHA256_Update(&sha, tx->src_signature.r, sizeof(tx->src_signature.r));
	SHA256_Update(&sha, tx->src_signature.s, sizeof(tx->src_signature.s));
	SHA256_Final(h, &sha);
}

/* Set the prev_transaction_hash field to a fixed value. */
void transaction_set_prev_transaction_hash(struct transaction *tx, const hash_output prev_transaction_hash)
{
	memmove(tx->prev_transaction_hash, prev_transaction_hash, sizeof(tx->prev_transaction_hash));
}

/* Set the prev_transaction_hash field to the hash of the given prev_tx. The
 * special value prev_tx==NULL means there is no previous transaction; i.e.,
 * this is either a reward transaction or it is an unused normal transaction. */
void transaction_set_prev_transaction(struct transaction *tx, const struct transaction *prev_tx)
{
	hash_output h;

	if (prev_tx == NULL) {
		memset(tx->prev_transaction_hash, 0, sizeof(tx->prev_transaction_hash));
		return;
	}

	transaction_hash(prev_tx, h);
	transaction_set_prev_transaction_hash(tx, h);
}

/* A wrapper around BN_bn2bin that left-pads with zero bytes. If bn does not fit
 * in len bytes, returns 0 to indicate an error; otherwise returns 1. */
static int bn2bin(const BIGNUM *bn, unsigned char *dest, size_t len)
{
	int num_bytes;

	num_bytes = BN_num_bytes(bn);
	if (num_bytes > len)
		return 0;
	BN_bn2bin(bn, dest + len - num_bytes);
	return 1;
}

/* Set the destination public key of this transaction to the given public key.
 * Returns 1 for success; 0 for error. */
int transaction_set_dest_pubkey(struct transaction *tx,
	const EC_GROUP *group, const EC_POINT *pubkey)
{
	BIGNUM *x, *y;
	int rc;

	x = BN_new();
	if (x == NULL)
		goto err;
	y = BN_new();
	if (y == NULL)
		goto err;
	rc = EC_POINT_get_affine_coordinates_GFp(group, pubkey, x, y, NULL);
	if (rc != 1)
		goto err;
	if (bn2bin(x, tx->dest_pubkey.x, sizeof(tx->dest_pubkey.x)) != 1)
		goto err;
	if (bn2bin(y, tx->dest_pubkey.y, sizeof(tx->dest_pubkey.y)) != 1)
		goto err;

	BN_free(x);
	BN_free(y);

	return 1;

err:
	if (x != NULL)
		BN_free(x);
	if (y != NULL)
		BN_free(y);

	return 0;
}

/* Set the destination public key of this transaction to the public part of the
 * given private key. Returns 1 for success; 0 for error. */
int transaction_set_dest_privkey(struct transaction *tx, const EC_KEY *privkey)
{
	return transaction_set_dest_pubkey(tx,
		EC_KEY_get0_group(privkey), EC_KEY_get0_public_key(privkey));
}

/* Sign this transaction using the given private key. Returns 1 for success; 0
 * for error. */
int transaction_sign(struct transaction *tx, EC_KEY *key)
{
	unsigned char uint32_buf[4];
	SHA256_CTX sha;
	ECDSA_SIG *sig;
	BIGNUM *x, *y;
	hash_output h;

	sig = NULL;
	x = NULL;
	y = NULL;

	/* Signing this transaction, we ignore the src_signature field
	 * itself. */
	SHA256_Init(&sha);
	serialize_uint32(uint32_buf, tx->height);
	SHA256_Update(&sha, uint32_buf, sizeof(uint32_buf));
	SHA256_Update(&sha, tx->prev_transaction_hash, sizeof(tx->prev_transaction_hash));
	SHA256_Update(&sha, tx->dest_pubkey.x, sizeof(tx->dest_pubkey.x));
	SHA256_Update(&sha, tx->dest_pubkey.y, sizeof(tx->dest_pubkey.y));
	SHA256_Final(h, &sha);

	sig = ECDSA_do_sign(h, sizeof(h), key);
	if (sig == NULL)
		goto err;

	/* Copy the signature into the transaction's byte arrays. */
	memset(tx->src_signature.r, 0, sizeof(tx->src_signature.r));
	memset(tx->src_signature.s, 0, sizeof(tx->src_signature.s));
	if (bn2bin(sig->r, tx->src_signature.r, sizeof(tx->src_signature.r)) != 1)
		goto err;
	if (bn2bin(sig->s, tx->src_signature.s, sizeof(tx->src_signature.s)) != 1)
		goto err;

	ECDSA_SIG_free(sig);
	BN_free(x);
	BN_free(y);

	return 1;

err:
	if (sig != NULL)
		ECDSA_SIG_free(sig);
	if (x != NULL)
		BN_free(x);
	if (y != NULL)
		BN_free(y);

	return 0;
}

/* Verify the signature on this transaction using the public key
 * prev_tx->dest_pubkey. The return value is:
 *  1 for successful verification;
 *  0 for failed verification;
 * -1 for any runtime error. */
int transaction_verify(struct transaction *tx, const struct transaction *prev_tx)
{
	unsigned char uint32_buf[4];
	SHA256_CTX sha;
	hash_output h;
	EC_KEY *pubkey;
	ECDSA_SIG *sig;
	BIGNUM *x, *y;
	int v, rc;

	pubkey = NULL;
	sig = NULL;
	x = NULL;
	y = NULL;

	SHA256_Init(&sha);
	serialize_uint32(uint32_buf, tx->height);
	SHA256_Update(&sha, uint32_buf, sizeof(uint32_buf));
	SHA256_Update(&sha, tx->prev_transaction_hash, sizeof(tx->prev_transaction_hash));
	SHA256_Update(&sha, tx->dest_pubkey.x, sizeof(tx->dest_pubkey.x));
	SHA256_Update(&sha, tx->dest_pubkey.y, sizeof(tx->dest_pubkey.y));
	SHA256_Final(h, &sha);

	x = BN_bin2bn(prev_tx->dest_pubkey.x, sizeof(prev_tx->dest_pubkey.x), NULL);
	if (x == NULL)
		goto err;
	y = BN_bin2bn(prev_tx->dest_pubkey.y, sizeof(prev_tx->dest_pubkey.y), NULL);
	if (y == NULL)
		goto err;

	pubkey = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (pubkey == NULL)
		goto err;
	rc = EC_KEY_set_public_key_affine_coordinates(pubkey, x, y);
	if (rc != 1) {
		EC_KEY_free(pubkey);
		BN_free(x);
		BN_free(y);
		return 0;
	}

	BN_free(x);
	x = NULL;
	BN_free(y);
	y = NULL;

	sig = ECDSA_SIG_new();
	if (sig == NULL)
		goto err;

	sig->r = BN_bin2bn(tx->src_signature.r, sizeof(tx->src_signature.r), sig->r);
	if (sig->r == NULL)
		goto err;
	sig->s = BN_bin2bn(tx->src_signature.s, sizeof(tx->src_signature.s), sig->s);
	if (sig->s == NULL)
		goto err;

	v = ECDSA_do_verify(h, sizeof(h), sig, pubkey);

	EC_KEY_free(pubkey);
	ECDSA_SIG_free(sig);

	return v;

err:
	if (pubkey != NULL)
		EC_KEY_free(pubkey);
	if (sig != NULL)
		ECDSA_SIG_free(sig);
	if (x != NULL)
		BN_free(x);
	if (y != NULL)
		BN_free(y);

	return -1;
}
