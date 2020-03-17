#include "dbe2.h"
#include <pbc/pbc_test.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NUMTEST 100

extern BilinearGroup bilinearGroup;
extern Users users[MAX_USER];
extern Param param;

void random_set(Set *S, int len, int n, int N) {
  S->len = len;
  srand(time(NULL));

  // users[0]..[n-1] is not revoked
  for (size_t i = 0; i < len; i++) {
    S->s[i] = i + n;
  }

  for (size_t j = 0; j < len; j++) {
    int r = j + rand() % (len - j);
    int t = S->s[r];
    S->s[r] = S->s[j];
    S->s[j] = t;
  }
}

int main(int argc, char const *argv[]) {
  SetupBilinearGroup();
  int n = 10; // Number of key users
  int N, r;
  N = atoi(argv[1]); // Number of users
  r = atoi(argv[2]); // Number of revoked users

  double time1, time2;
  time1 = pbc_get_time();

  Setup(n, N);
  //    printf ("\nSetup (%d, %d): %fs\n", n, N, (time2 - time1)*1000.0);
  Set R; // = {5, {10,12,13,14, 15}};>
  random_set(&R, r, n, N);

  for (size_t i = 0; i < R.len; i++) {
    Extract(R.s[i]);
  }

  double everage = 0;
  // for (int l = 0; l < NUMTEST; ++l) {
  // time1 = pbc_get_time();
  // Extract(11);
  // time2 = pbc_get_time();
  // everage += (time2 - time1);
  //   }
  //   printf("\nExtract: %fms & \t", everage * 1000.0 / NUMTEST);
  element_t K;
  Hdr hdr;
  everage = 0;
  for (int l = 0; l < NUMTEST; ++l) {
    time1 = pbc_get_time();
    Encrypt(K, &hdr, &R);
    time2 = pbc_get_time();
    everage += (time2 - time1);
  }
  printf("\nEncrypt: %fms & \t", everage * 1000.0 / NUMTEST);

  element_t K1;

  everage = 0;
  for (int l = 0; l < NUMTEST; ++l) {
    time1 = pbc_get_time();
    Decrypt(K1, users[0].d, 0, &hdr, &R);
    time2 = pbc_get_time();
    everage += (time2 - time1);
  }
  printf("\nDecrypt: %fms & \t\n", everage * 1000.0 / NUMTEST);

  // if (!element_cmp(K, K1))
  //   printf("OK");
  // else
  //   printf("Not OK");

  return 0;
}