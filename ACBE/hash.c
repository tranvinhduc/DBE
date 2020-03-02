//
// Created by Tran Vinh Duc on 2/29/20.
//
#include "hash.h"

// Sha256
void H(unsigned char out[crypto_hash_sha256_BYTES], unsigned char buffer[], size_t len)
{
    crypto_hash_sha256_state sha_state;
    crypto_hash_sha256_init(&sha_state);
    crypto_hash_sha256_update(&sha_state, buffer, len);
    crypto_hash_sha256_final(&sha_state, out);
}
void H1 (element_t out, int IDi, element_t Q)
{
    union {
        int i;
        unsigned char a[4];
    } Id = {IDi};

    unsigned char q[1024];
    size_t qlen = element_length_in_bytes(Q) + sizeof(int);
    for(int j = 0; j < sizeof(int); j++)
        q[j] = Id.a[j];

    element_to_bytes(q+sizeof(int), Q);

    unsigned char sha[crypto_hash_sha256_BYTES];
    H(sha, q, qlen);
//    char* sha1=malloc(sizeof(sha)*2+1);
//    sodium_bin2hex(sha1, sizeof(sha)*2+1, sha, sizeof(sha));
//    printf("body sha256:\n%s\n",sha1);
    element_from_hash(out, sha, crypto_hash_sha256_BYTES);
}

void H2(element_t out, int IDi, element_t P, element_t Q)
{
    union {
        int i;
        unsigned char a[4];
    } Id = {IDi};
    unsigned char q[1024];
    size_t len = element_length_in_bytes(P);
    for(int j = 0; j < sizeof(int); j++)
        q[j] = Id.a[j];
    element_to_bytes(q + sizeof(int), P);
    element_to_bytes(q + sizeof(int) + len, Q);

    unsigned char sha[crypto_hash_sha256_BYTES];     // Hash with Sha256
    H(sha, q, 2*len +sizeof(int));

    element_from_hash(out, sha, crypto_hash_sha256_BYTES);
}

void H3 (element_t out, unsigned char M[MESSAGE_LEN], element_t K)
{
    unsigned char q[1024];

    memcpy (q, M, MESSAGE_LEN);
    size_t lenK = element_length_in_bytes(K);
    element_to_bytes(q + MESSAGE_LEN, K);

    unsigned char sha[crypto_hash_sha256_BYTES];     // Hash with Sha256
    H(sha, q, lenK + MESSAGE_LEN);

    element_from_hash(out, sha, crypto_hash_sha256_BYTES);
}

void H4 (unsigned char out[PARAM_W], element_t chi)
{
    unsigned char q[1024];
    size_t len = element_length_in_bytes(chi);
    element_to_bytes(q, chi);
    H(out, q, len);
}

void H5 (unsigned char out[MESSAGE_LEN], element_t K)
{
    unsigned char q[1024];
    size_t len = element_length_in_bytes(K);
    element_to_bytes(q, K);
    H(out, q, len);
}
