#ifndef OVTS_H
#define OVTS_H
#include <time.h>
#include "common.h"
#include "paillier.h"
#include "ecdsa.h"

extern "C"
{
#include "miracl.h"
}

extern PFC pfc;

typedef struct _OVTS_SYS_PARAMETER
{
	int la;
	ECn G;
	Big q;
	Big n;
	Big n2;
	Big g;
	Big h;
}ovtsSysPara;

typedef struct _OVTS_WITNESS_
{
	Big ws;
	Big walpha;
	Big wbeta;
	Big wlambda;
	Big wr1;
	Big wr2;
	Big wr3;
	Big wdelta;
	Big wphi;
}ovtsW;

typedef struct _OVTS_STATE_
{
	Big xn;
	Big xg;
	Big xh;
	Big xct;
	Big ixct;
	Big xu;
	Big ixu;
	Big xv;
	Big ixv;
	Big xr;
	ECn xK;
	Big xHm;
	ECn xG;
	ECn xP;
	Big xR;
	Big ixR;
	ECn xR1;
	ECn xR2;
	Big xg1;
	Big ixg1;
	ECn xG2;
	ECn xH2;
}ovtsX;

typedef struct _OVTS_PI_
{
	Big c;
	Big zs;
	Big zalpha;
	Big zbeta;
	Big zlambda;
	Big zr1;
	Big zr2;
	Big zr3;
	Big zdelta;
	Big zphi;
}ovtsPi;

#endif


void CommitProve(miracl *mip, ovtsSysPara opara, ecdsaSig ecdsaSig, paiPriKey sk, ovtsX &ox, ovtsW &ow, ovtsPi &opi);
void NIZKProve(miracl *mip, ovtsSysPara opara, ovtsX ox, ovtsW ow, ovtsPi &opi);
int NIZKVerf(miracl *mip, ovtsSysPara opara, ECn PK, ovtsX ox, ovtsPi opi);
