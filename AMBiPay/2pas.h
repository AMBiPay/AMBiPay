#ifndef PAS_H
#define PAS_H

#include "ecdsa.h"
#include "bls.h"
#include "paillier.h"

extern "C"
{
#include "miracl.h"
}

#define NBYTELEN 128
extern PFC pfc;

typedef struct _NIZK_DLOG_X_
{
	ECn Y;

}nizkDLX;

typedef struct _NIZK_DLOG_W_
{
	Big w;

}nizkDLW;

typedef struct _NIZK_DLOG_PI_
{
	Big e;
	Big z;
}nizkDLPi;

typedef struct _PS_ECDSA_
{
	Big r;
	Big ws;
	ECn Y0;
	Big e0;
	Big z0;
	int b;
}pSigma;

typedef struct _PS_ECDSA2_
{
	Big r;
	Big ws;
	ECn Y0;
	ECn Zg;
	Big e0;
	Big z0;
	Big zs;
	int b;
}pSigma2;



typedef struct _SCHNORR_SYS_PARA_
{
	int la;
	Big p;
	Big a;
	Big b;
	ECn G;
	Big n;
}schnorrSysPara;

typedef struct _SCHNORR_SIG_
{
	ECn R;
	Big s;
}schnorrSig;

typedef struct _PS_SCHNORR_
{
	ECn R;
	Big ws;
	ECn Y0;
	Big e0;
	Big z0;
}pSigSchnorr;


typedef struct _PS_BLS_
{
	G1 ws;
	GT Y0;
	Big e0;
	G1 z0;
}pSigma1;

extern void Hash(BYTE *input, Big &h);
void nizkProveDL(ecdsaSysPara sysPara, nizkDLX st, nizkDLW wit, nizkDLPi & pi);
int nizkVerfDL(ecdsaSysPara sysPara, nizkDLX st, nizkDLPi pi);
void P0Comit(ecdsaSysPara sysPara, nizkDLX &st0, nizkDLW &wi0, nizkDLPi &pi0, Big &cm0);
void P1Comit(ecdsaSysPara sysPara, nizkDLX &st1, nizkDLW &wi1, nizkDLPi &pi1);
int P1Sign(ecdsaSysPara sysPara, Big cm0, nizkDLX st0, nizkDLPi pi0, Big d1, BYTE *msg, int msgByteLen, nizkDLW wi1, paiPubKey pk0, Big d0cipher, Big &cipher);
int P1SignOffline(ecdsaSysPara sysPara, Big cm0, nizkDLX st0, nizkDLPi pi0, Big d1, nizkDLW wi1, paiPubKey pk0, Big d0cipher, Big &cpart, Big &cinvk);
int P1SignOnline(ecdsaSysPara sysPara, nizkDLX st0, nizkDLPi pi0, BYTE *msg, int msgByteLen, paiPubKey pk0, Big cpart, Big  cinvk, Big &cipher);
void P0Sign(ecdsaSysPara sysPara, nizkDLX st1, nizkDLW wi0, paiPriKey sk0, paiPubKey pk0, Big cipher, ecdsaSig &sigma);
void pSignECDSA(ecdsaSysPara sysPara, ecdsaSig sigma, BYTE *msg, int msgByteLen, ECn K, ECn P, Big y0, pSigma &psig);
void pSignECDSAOffline(ecdsaSysPara sysPara, ECn K, ECn P, Big y0, pSigma &psig);
void pSignECDSAOnline(ecdsaSysPara sysPara, ecdsaSig sigma, Big y0, pSigma &psig);

int pVerfECDSA(ecdsaSysPara sysPara, ECn P, BYTE *msg, int msgByteLen, pSigma psig);
void adaptECDSA(ecdsaSysPara sysPara, pSigma psig, Big y0, ecdsaSig &sig);
void extECDSA(ecdsaSysPara sysPara, pSigma psig, ecdsaSig sig, Big &y0);

void pSignECDSA(ecdsaSysPara sysPara, ecdsaSig sigma, BYTE *msg, int msgByteLen, ECn K, ECn P, Big y0, pSigma2 &psig);
void pSignECDSAOffline(ecdsaSysPara sysPara, ECn K, ECn P, Big y0, ECn &R0, ECn &Rg, ECn &Rk, Big &r0, Big &rs, pSigma2 &psig);
void pSignECDSAOnline(ecdsaSysPara sysPara, ECn R0, ECn Rg, ECn Rk, ECn K, ecdsaSig sigma, Big r0, Big rs, Big y0, pSigma2 &psig);
int pVerfECDSA(ecdsaSysPara sysPara, ECn P, BYTE *msg, int msgByteLen, pSigma2 psig);
void adaptECDSA(ecdsaSysPara sysPara, pSigma2 psig, Big y0, ecdsaSig &sig);
void extECDSA(ecdsaSysPara sysPara, pSigma2 psig, ecdsaSig sig, Big &y0);


void signSchnorr(ecdsaSysPara sysPara, ECn R, Big r, Big d, BYTE *msg, int msgByteLen, schnorrSig &sig);
int verfSchnorr(ecdsaSysPara sysPara, ECn P, BYTE *msg, int msgByteLen, schnorrSig sig);
void psign2Schnorr(ecdsaSysPara sysPara, ECn P, Big y0, BYTE *msg, int msgByteLen, schnorrSig sig, pSigSchnorr &psig);
void psign2SchnorrOnline(ecdsaSysPara sysPara, ECn P, Big y0, schnorrSig sig, pSigSchnorr &psig);
void psign2SchnorrOffline(ecdsaSysPara sysPara, Big y0, BYTE *msg, int msgByteLen, schnorrSig sig, pSigSchnorr &psig);
int pverfSchnorr(ecdsaSysPara sysPara, ECn P, BYTE *msg, int msgByteLen, schnorrSig sig, pSigSchnorr psig);
void adaptSchnorr(ecdsaSysPara sysPara, pSigSchnorr psig, Big y0, schnorrSig &sig);
void extSchnorr(ecdsaSysPara sysPara, schnorrSig sig, pSigSchnorr psig, Big &y0);

void pSignBLS(blsSysPara sysPara, G1 sigma, BYTE *msg, int msgByteLen, G1 y0, pSigma1 &psig);
void pSignBLSOnline(blsSysPara sysPara, G1 sigma, BYTE *msg, int msgByteLen, G1 y0, pSigma1 &psig);
void pSignBLSOffline(blsSysPara sysPara, G1 sigma, BYTE *msg, int msgByteLen, G1 y0, pSigma1 &psig);
int pVerfBLS(blsSysPara sysPara, BYTE *msg, int msgByteLen, G2 P, pSigma1 psig);
void adaptBLS(blsSysPara sysPara, pSigma1 psig, G1 y0, G1 &sigma);
void extBLS(blsSysPara sysPara, pSigma1 psig, G1 sigma, G1 &y0);
#endif
