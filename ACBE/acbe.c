//
// Created by Tran Vinh Duc on 2/28/20.
//

#include <assert.h>
#include "acbe.h"

//#define PATH "../../param/a.param"

pairing_t pairing;
Param param;
element_t MK;
Users users[MAX_USER];
void pairing_init() 
{
    char input[1024];
 //   FILE *f = fopen(PATH,"r");
 //   size_t count = fread(input, 1, 1024, f);
 
    size_t count = fread(input, 1, 1024, stdin);
 
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, input, count);
}

void Setup()
{
    element_init_G1(param.g, pairing);
    element_init_G1(param.g1, pairing);
    element_init_GT(param.gT, pairing);
    element_init_Zr(MK, pairing);

    element_random(param.g);
    element_random(MK);
    element_pow_zn(param.g1, param.g, MK);

    pairing_apply(param.gT, param.g, param.g, pairing);
}

void KeyGen(int IDi)
{
    element_init_Zr(users[IDi].sk, pairing);
    element_random(users[IDi].sk);

    element_init_G1(users[IDi].pk, pairing);
    element_pow_zn(users[IDi].pk, param.g, users[IDi].sk);
}

int IsValid(element_t cert, element_t Q)
{
    element_t l, r;
    element_init_GT(l, pairing);
    element_init_GT(r, pairing);
    pairing_apply (l, param.g, cert, pairing);
    pairing_apply (r, param.g1, Q, pairing);
    return element_cmp(l, r);

}
int CertGen(int IDi, element_t PKi)
{
    element_init_G1(users[IDi].Q, pairing);
    H1(users[IDi].Q, IDi, PKi);

    element_init_G1(users[IDi].R, pairing);
    H2(users[IDi].R, IDi, PKi, param.g1);

    element_init_GT(users[IDi].e1, pairing);
    pairing_apply(users[IDi].e1, param.g1, users[IDi].Q, pairing);
    element_init_GT(users[IDi].e2, pairing);
    pairing_apply(users[IDi].e2, PKi, users[IDi].R, pairing);

    element_init_G1(users[IDi].cert, pairing);
    element_pow_zn(users[IDi].cert, users[IDi].Q, MK);
    return IsValid(users[IDi].cert, users[IDi].Q);
}

void Encrypt(CipherText *CT, Set *S, unsigned char M[MESSAGE_LEN])
{
    element_t K;
    element_init_GT(K, pairing);
    element_random(K);

    //element_printf("K=%B\n", K);

    element_t r;
    element_init_Zr(r, pairing);
    H3(r, M, K);
    element_init_G1(CT->hdr.C0, pairing);
    element_pow_zn(CT->hdr.C0, param.g, r);
    element_t chi;

    CT->hdr.len = S->len;
    element_init_GT(chi, pairing);
    for (int i = 0; i < S->len; ++i) {
       element_mul(chi, users[S->s[i]].e1, users[S->s[i]].e2);
       element_pow_zn(chi, chi, r);
       element_invert(chi, chi);
       H4(CT->hdr.C[i].C1i_1, chi);
       element_init_GT(CT->hdr.C[i].C1i_2, pairing);
       element_mul(CT->hdr.C[i].C1i_2, K, chi);
    }
    unsigned char K_[MESSAGE_LEN];
    H5(K_,K);
    for (int j = 0; j < MESSAGE_LEN; ++j) {
        CT->cipherText[j] = M[j]^K_[j];
    }
}

void Decrypt(unsigned char M[MESSAGE_LEN], CipherText *CT,
             int IDi, element_t sk, element_t cert)
{
    element_t chi;
    element_init_GT(chi, pairing);

    element_t l, r;
    element_init_GT(l, pairing);
    element_init_GT(r, pairing);

    pairing_apply(l, CT->hdr.C0, cert, pairing);

    pairing_apply(r, CT->hdr.C0, users[IDi].R, pairing);
    element_pow_zn(r, r, sk);
    element_mul(chi, l, r);

    element_t chi_;
    element_init_GT(chi_, pairing);
    element_invert(chi_, chi);
    unsigned char C1i_1[PARAM_W];
    H4(C1i_1, chi_);

    int i;
    for (i = 0; i < CT->hdr.len; ++i) {
        if (!memcmp(C1i_1, CT->hdr.C[i].C1i_1, PARAM_W))
            break;
    }
    if (i==CT->hdr.len)
    {
        printf(" Not found!");
        return;
    }

    element_t K;
    element_init_GT(K, pairing);
    element_mul(K, CT->hdr.C[i].C1i_2,chi);

    //element_printf("K'=%B\n",K);
    unsigned char K_[MESSAGE_LEN];
    H5(K_,K);
    for (int j = 0; j < MESSAGE_LEN; ++j) {
        M[j] = CT->cipherText[j] ^K_[j];
    }
}
