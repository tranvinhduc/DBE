#include <stdio.h>
#include<string.h>
#include <time.h>
#include<stdlib.h>
#include "acbe.h"
#include <sodium.h>
#include <pbc/pbc_test.h>

#define NUMTEST 100

extern pairing_t pairing;
extern Param param;
extern element_t MK;
extern Users users[MAX_USER];

void random_set(Set *S, int len)
{
    S->len = len;
    srand(time(NULL));
    for (size_t i = 0; i < MAX_USER; i++)
    {
        S->s[i] = i;
    }
    for (size_t j = 0; j < len; j++)
    {
        int r = j + rand() % (MAX_USER - j);
        int t = S->s[r];
        S->s[r] = S->s[j];
        S->s[j] = t;
    }
}


int main(int argc, char const *argv[]) 
{
    pairing_init();
    double time1, time2;
    time1 = pbc_get_time();
    Setup();
    time2 = pbc_get_time();
    //printf ("\nSetup (): %fs\n", (time2 - time1)*1000.0);

    int N = atoi(argv[1]);
    int r= atoi(argv[2]);
   // printf ("n = %d", n);
    int n = N -r;

    Set S; random_set(&S, n);
    for (int i = 0; i < S.len; ++i) {
        KeyGen(S.s[i]);
        CertGen(S.s[i], users[S.s[i]].pk);
    }

    CipherText CT;
    unsigned char M[MESSAGE_LEN];
    H(M, (unsigned char*)"ACBE",4);
    
    double everage = 0; 
    for (int l = 0; l < NUMTEST; ++l) {
        time1 = pbc_get_time();
        Encrypt(&CT, &S, M);
        time2 = pbc_get_time();
        everage += (time2 - time1);
    }
    printf("\nEncrypt: %fms & \t", everage * 1000.0 / NUMTEST);


    unsigned char M2[MESSAGE_LEN];
    everage = 0; 
    for (int l = 0; l < NUMTEST; ++l) {
        time1 = pbc_get_time();
        Decrypt(M2, &CT, S.s[1], users[S.s[1]].sk, users[S.s[1]].cert);
        time2 = pbc_get_time();
        everage += (time2 - time1);
    }
    printf("\n Decrypt: %fms & \t", everage * 1000.0 / NUMTEST);

    /*
    if(!memcmp(M,M2,MESSAGE_LEN))
        printf ("OK\n");
    else printf("Not OK\n");
    */
    return 0;
}
