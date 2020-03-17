//
// Created by Tran Vinh Duc on 2/24/20.
//

#include "dbe2.h"

BilinearGroup bilinearGroup;
int N;  //Maximum users in system
int n;  // Number of Key Users

Users users[MAX_USER];
Param param;

void SetupBilinearGroup()
{
    char input[1024];
    size_t count = fread(input, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(bilinearGroup.pairing, input, count);

    element_init_G1(bilinearGroup.g, bilinearGroup.pairing);
    element_random(bilinearGroup.g);
    element_init_G2(bilinearGroup.g_, bilinearGroup.pairing);
    element_random(bilinearGroup.g_);
}


void SetupKU(int i)  // Init for Key r i
{
    element_t a;
    element_init_Zr(a, bilinearGroup.pairing);
    element_random(a);

    element_init_G2(users[i].g_Alpha, bilinearGroup.pairing);
    element_pow_zn(users[i].g_Alpha, bilinearGroup.g_, a);


    //e(g,g_)^a
    element_init_GT(users[i].eAlpha, bilinearGroup.pairing);
    pairing_apply(users[i].eAlpha, bilinearGroup.g, users[i].g_Alpha, bilinearGroup.pairing);

    element_clear(a);

    element_t b;
    element_init_Zr(b, bilinearGroup.pairing);
    element_random(b);

    element_init_G1(users[i].gBeta, bilinearGroup.pairing);
    element_pow_zn(users[i].gBeta, bilinearGroup.g, b);       //g^b

    element_init_G2(users[i].g_Beta, bilinearGroup.pairing);
    element_pow_zn(users[i].g_Beta, bilinearGroup.g_, b);       //g~^b

    element_clear(b);

    for (int j = 0; j < N; ++j) {
        element_t r;
        element_init_Zr(r, bilinearGroup.pairing);
        element_random(r);

        element_init_G1(users[i].gr[j], bilinearGroup.pairing);
        element_pow_zn(users[i].gr[j], bilinearGroup.g, r);       //g^r

        element_init_G2(users[i].g_r[j], bilinearGroup.pairing);
        element_pow_zn(users[i].g_r[j], bilinearGroup.g_, r);       //g~^r

        element_clear(r);
    }
}

// Each key r i, Generating Partial Secret Key for  r j
void GeneratePartialSecreteKey(PartialSecreteKey *partialSecretKey, int i, int j)
{
    //random element s_{ij}
    element_t s;
    element_init_Zr(s, bilinearGroup.pairing);
    element_random(s);

    // d^i_{j0}
    element_init_G2(partialSecretKey->d0, bilinearGroup.pairing);
    element_pow_zn(partialSecretKey->d0, param.g_Beta, s);
    element_mul(partialSecretKey->d0, partialSecretKey->d0, users[i].g_Alpha); // Use secret users[i]

    // d'^i_{j0}
    element_init_G2(partialSecretKey->d_0, bilinearGroup.pairing);
    element_pow_zn(partialSecretKey->d_0, bilinearGroup.g_, s);

    // d^i_{jk}
    for (int k = 0; k < N; ++k) {
        element_init_G2(partialSecretKey->d[k], bilinearGroup.pairing);
        element_pow_zn(partialSecretKey->d[k], param.u_[k], s);
    }
    element_set0(partialSecretKey->d[j]);       // not compute d_{jj}
}


// Compute secret key for User j
void Extract(int j)
{
    for (int i = 0; i < param.S.len; ++i) {
        GeneratePartialSecreteKey(&users[j].d[i], param.S.s[i], j);
    }
}
void Setup(int nKeyUsers, int NUsers)
{
    element_init_G1(param.g, bilinearGroup.pairing);
    element_set(param.g, bilinearGroup.g);

    n = nKeyUsers;
    N = NUsers;

    // Initialization for Key Users
    for (int i = 0; i < n; ++i) {
        SetupKU(i);
    }

    //Phase 1: Compute param
    element_init_GT(param.eAlpha, bilinearGroup.pairing);
    element_set1(param.eAlpha);
    element_init_G1(param.gBeta, bilinearGroup.pairing);
    element_set1(param.gBeta);
    element_init_G2(param.g_Beta, bilinearGroup.pairing);
    element_set1(param.g_Beta);

    //Compute e(g,g~)^alpha, g^beta, g~^beta
    for (int i = 0; i < n; ++i) {
        element_mul(param.eAlpha, param.eAlpha, users[i].eAlpha);
        element_mul(param.gBeta, param.gBeta, users[i].gBeta);
        element_mul(param.g_Beta, param.g_Beta, users[i].g_Beta);
    }

    // non-mal-functioning key users S = [n]
    param.S.len = n;
    for (int i = 0; i < n; ++i) {
        param.S.s[i] = i;
    }

    for (int j = 0; j < N; ++j) {
        element_init_G1(param.u[j], bilinearGroup.pairing);
        element_set1(param.u[j]);
        element_init_G2(param.u_[j], bilinearGroup.pairing);
        element_set1(param.u_[j]);

        //uj, u~j
        for (int i = 0; i < n; ++i) {
            element_mul(param.u[j], param.u[j], users[i].gr[j]);
            element_mul(param.u_[j], param.u_[j], users[i].g_r[j]);
        }
    }

    //Phase 2: Generating the secret key for key user i
    for (int i = 0; i < n; ++i) {
        Extract(i);
    }
}

// test if j is in S.
int in(int j, Set *S)
{
    for (int i = 0; i < S->len; ++i) {
        if(j == S->s[i]) return 1;
    }
    return 0;
}
//Update param
void Revoke (Set *S)
{
    element_set1(param.eAlpha);
    for (int i = 0; i < S->len; ++i) {
        element_mul(param.eAlpha, param.eAlpha, users[S->s[i]].eAlpha);
    }
    param.S.len = S->len;
    for (int i = 0; i < S->len; ++i) {
        param.S.s[i] = S->s[i];
    }
}
//
void Encrypt (element_t K, Hdr *hdr, Set *revokedUsers)
{
    element_t k;
    element_init_Zr(k, bilinearGroup.pairing);
    element_random(k);

    // Compute Header hdr = (C1, C2)
    element_init_G1(hdr->C1, bilinearGroup.pairing);
    element_pow_zn(hdr->C1, param.g, k);

    element_init_G1(hdr->C2, bilinearGroup.pairing);
    element_set(hdr->C2, param.gBeta);

    for (int i = 0; i < revokedUsers->len; ++i) {
        element_mul(hdr->C2, hdr->C2, param.u[revokedUsers->s[i]]);
    }
    element_pow_zn(hdr->C2, hdr->C2, k);

    // Compute K = e(g, g~)^{alpha.k}
    element_init_GT(K, bilinearGroup.pairing);
    element_pow_zn(K, param.eAlpha, k);
}

void Decrypt(element_t K, PartialSecreteKey d[], int j, Hdr *hdr, Set *revokedUsers){
    SecretKey dj;

    element_init_G2 (dj.d0, bilinearGroup.pairing);
    element_set1(dj.d0);
    element_init_G2(dj.d_0, bilinearGroup.pairing);
    element_set1(dj.d_0);
    for (int k = 0; k < N; ++k) {
        element_init_G2(dj.d[k],bilinearGroup.pairing);
        element_set1(dj.d[k]);
    }

    for (int i = 0; i < param.S.len; ++i) {
        element_mul(dj.d0, dj.d0, d[param.S.s[i]].d0);
        element_mul(dj.d_0, dj.d_0, d[param.S.s[i]].d_0);
    }
/*
    for (int k = 0; k < N; ++k) {
        for (int i = 0; i < param.S.len; ++i) {
            element_mul(dj.d[k],dj.d[k],d[param.S.s[i]].d[k]);
        }
    }
*/

// Change: Decryption time increases linearly on the number of Revoked Users, 
//                                        not on the Number of Users

    for (int k = 0; k < revokedUsers->len; ++k) {
        for (int i = 0; i < param.S.len; ++i) {
            element_mul(dj.d[revokedUsers->s[k]],dj.d[revokedUsers->s[k]],d[param.S.s[i]].d[revokedUsers->s[k]]);
        }
    }


    element_init_GT(K, bilinearGroup.pairing);
    if (in(j, revokedUsers)) return;

    // K = x/y
    element_t x, y;
    element_init_GT(x, bilinearGroup.pairing);
    element_init_GT(y, bilinearGroup.pairing);

    element_t x2;
    element_init_G2(x2, bilinearGroup.pairing);
    element_set(x2, dj.d0);
    for (int l = 0; l < revokedUsers->len; ++l) {
        element_mul(x2, x2, dj.d[revokedUsers->s[l]]);
    }

    pairing_apply(x, hdr->C1, x2, bilinearGroup.pairing);
    pairing_apply(y, hdr->C2, dj.d_0, bilinearGroup.pairing);

    // K = x/y
    element_div(K, x, y);
}