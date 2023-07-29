#ifndef ECDSA_H
#define ECDSA_H
#include <time.h>
#include "common.h"
#include "bls.h"
extern "C"
{
#include "miracl.h"
}

typedef struct _ECDSA_SYS_PARA_
{
	int la;
	Big p;
	Big a;
	Big b;
	ECn G;
	Big n;
}ecdsaSysPara;

typedef struct _ECDSA_SIG_
{
	Big r;
	Big s;
}ecdsaSig;




void Hash(BYTE *input, Big &h);
int ecdsaSetup(miracl *mip, ecdsaSysPara &sysPara, int la, Big p, Big a, Big b, Big xG, Big yG, Big n);
int ecdsaKGen(miracl *mip, ecdsaSysPara sysPara, Big &sk, ECn &PK);
int ecdsaKGen(miracl *mip, ecdsaSysPara sysPara, int factor, Big &sk, ECn &PK);
int ecdsaSign(miracl *mip, ecdsaSysPara sysPara, Big sk, BYTE *msg, int msgByteLen, ecdsaSig &ecdsaSig);
int ecdsaVerf(miracl *mip, ecdsaSysPara sysPara, ECn PK, BYTE *msg, int msgByteLen, ecdsaSig ecdsaSig);
int ecdsaVerf(miracl *mip, blsSysPara sysPara, G1 PK, BYTE *msg, int msgByteLen, ecdsaSig ecdsaSig);
#endif
