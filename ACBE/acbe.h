//
// Created by Tran Vinh Duc on 2/28/20.
//

#ifndef ACBE_ACBE_H
#define ACBE_ACBE_H

#include "hash.h"
#include "fix.h"

void pairing_init();

typedef struct {
    element_t g, g1, gT;
} Param;

typedef struct{
    int len;
    int s[MAX_USER];
} Set;

typedef struct {
    unsigned char C1i_1[PARAM_W];
    element_t C1i_2;
} Header1;
typedef struct {
    int len;
    element_t C0;
    Header1 C[MAX_USER];
} Header;
typedef struct {
    Header hdr;
    unsigned char cipherText[MESSAGE_LEN];
} CipherText;

typedef struct {
    // Precomputed
    element_t Q;
    element_t R;
    element_t e1;  // e(g1,Qi)
    element_t e2;  // e(PKi, Ri)

    element_t sk;  // keep it secret
    element_t pk;
    element_t cert;
} Users;



void Setup();
void KeyGen(int IDi);
int CertGen(int IDi, element_t PKi);
void Encrypt(CipherText *CT, Set *S, unsigned char M[32]);
void Decrypt(unsigned char M[MESSAGE_LEN],  CipherText *CT, int IDi, element_t sk, element_t cert);


#endif //ACBE_ACBE_H
