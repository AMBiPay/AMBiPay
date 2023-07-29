#ifndef BLS_H
#define BLS_H
#include <time.h>
#include "common.h"


extern PFC pfc;

#define COFATOR 2;

typedef struct _BLS_SYS_PARA_
{
	G1 g1;
	G2 g2;
	GT gt;
} blsSysPara;



void HashToG1(BYTE *msg, G1 &hash);
void blsSetup(BYTE *g1Byte, BYTE *g2Byte, BYTE *gtByte, blsSysPara &sysPara);
void blsKGen(blsSysPara sysPara, Big &sk, G2 &PK);
void blsSign(blsSysPara sysPara, Big sk, BYTE * msg, G1 &sig);
int blsVerf(blsSysPara sysPara, G2 PK, BYTE * msg, G1 sig);
#endif