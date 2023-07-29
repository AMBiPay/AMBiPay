#ifndef PAILLIER_H
#define PAILLIER_H

#include "common.h"
extern "C"
{
	#include "miracl.h"
}

typedef struct _PAIPUBKEY_
{
	Big N;
	Big N2;
	Big g;
}paiPubKey;

typedef struct _PAIPRIKEY_
{
	Big p;
	Big q;
	Big lambda;
	Big mu;
}paiPriKey;

void paillKGen(miracl *mip, int secPara, paiPubKey &pk, paiPriKey &sk);
void paillKGen(miracl *mip, int secPara, Big ecn, paiPubKey &pk, paiPriKey &sk);
void paillEnc(miracl *mip, paiPubKey pk, Big msg, Big &cipher);
void paillEncMont(miracl *mip, paiPubKey pk, Big msg, Big &cipher);
void paillDecMont(miracl *mip, paiPriKey sk, paiPubKey pk, Big cipher, Big &msg);
void paillDec(miracl *mip, paiPriKey sk, paiPubKey pk, Big cipher, Big &msg);
void paillDec(miracl *mip, paiPriKey sk, Big ecn, paiPubKey pk, Big cipher, Big &msg);
#endif // PAILLIER_H

