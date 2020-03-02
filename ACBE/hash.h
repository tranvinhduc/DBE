//
// Created by Tran Vinh Duc on 2/29/20.
//

#ifndef ACBE_HASH_H
#define ACBE_HASH_H
#include <sodium.h>
#include <pbc/pbc.h>
#include <string.h>

#define MESSAGE_LEN crypto_hash_sha256_BYTES
#define PARAM_W crypto_hash_sha256_BYTES

void H(unsigned char out[crypto_hash_sha256_BYTES], unsigned char buffer[], size_t len); //Sha256
void H1 (element_t out, int IDi, element_t Q);
void H2(element_t out, int IDi, element_t P, element_t Q);
void H3 (element_t out, unsigned char M[MESSAGE_LEN], element_t K);
void H4 (unsigned char out[PARAM_W], element_t chi);
void H5 (unsigned char out[MESSAGE_LEN], element_t K);

#endif //ACBE_HASH_H
