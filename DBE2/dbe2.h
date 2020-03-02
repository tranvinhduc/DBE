//
// Created by Tran Vinh Duc on 2/24/20.
//

#ifndef DBE1_DBE_H
#define DBE1_DBE_H
#include <pbc/pbc.h>
#include "fix_params.h"


typedef struct {
    element_t g, g_;
    pairing_t pairing;
} BilinearGroup;

void SetupBilinearGroup();

typedef struct{
    element_t d0;
    element_t d_0;    //d'j0
    element_t d[MAX_USER];     // djk
} SecretKey;

typedef  SecretKey PartialSecreteKey;
// Each key r i, Generating Partial Secret Key for  r j
void GeneratePartialSecreteKey(PartialSecreteKey *partialSecreteKey, int i, int j);

// Define Users
typedef struct {
    struct {    // Public
        element_t eAlpha;           //e(g,g_)^\alpha_i
        element_t gBeta, g_Beta;    //g^beta_i, \tidle{g}^\beta_i
        element_t gr[MAX_USER], g_r[MAX_USER];    //g^{r_1}..g^{r_N}, g~^{r_1}..g~^{r_N}
    };
    element_t g_Alpha;              //keeps it secret
    PartialSecreteKey d[MAX_KEY_USER];
} Users;
void SetupKU(int i);  // Init for Key user i

typedef struct{
    int len;
    int s[MAX_USER];
} Set;
// test if j is in S
int in(int j, Set *S);


typedef struct{
  element_t g;
  element_t gBeta, g_Beta;
  element_t u[MAX_USER];
  element_t u_[MAX_USER];
  element_t eAlpha;
  Set S;  //non-mal functioning key users S
} Param;


typedef struct{
    int len;
    int kU[MAX_KEY_USER];
} KeyUsers;


typedef struct {
    element_t C1, C2;
} Hdr;


// key users co-operate to generate the public parameter and secret key for each key r
void Setup(int nKeyUsers, int NUsers);
// Compute secret key for User j
void Revoke (Set *S);
void Extract(int j);
void Encrypt (element_t K, Hdr *hdr, Set *revokedUsers);
void Decrypt(element_t K, PartialSecreteKey d[], int j, Hdr *hdr, Set *revokedUsers);


#endif //DBE1_DBE_H
