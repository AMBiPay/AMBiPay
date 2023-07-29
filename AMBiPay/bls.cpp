#include "bls.h"



/***********************************
Description: H:{0,1}^* -> G1
Input: msg: message of BYTE type
Output: hash: hash value of G1 type
***********************************/
void HashToG1(BYTE *msg, G1 &hash)
{
	Big h;
	pfc.start_hash();
	pfc.add_to_hash((char*)msg);
	h = pfc.finish_hash_to_group();
	while (!hash.g.set(h, h))
	{
		h += 1;
	}
	hash.g *= *pfc.cof;   // using the cofactor to compute a generator of group G1
	hash.mtable = NULL;
	hash.mtbits = 0;
	
}

/***********************************
Description: setup of BLS scheme
Input: g1Byte: G1 generator of BYTE type,
	  g2Byte: G2 generator of BYTE type,
	  gtByte: GT generator of BYTE type	  
Output: sysPara: public system parameter of BLS scheme
***********************************/
void blsSetup(BYTE *g1Byte, BYTE *g2Byte, BYTE *gtByte, blsSysPara &sysPara)
{
	G1 g1;
	G2 g2;
	GT gt;
	byteToG1(g1Byte, g1);
	byteToG2(g2Byte, g2);
	byteToGT(gtByte, gt);
	sysPara.g1 = g1;
	sysPara.g2 = g2;
	sysPara.gt = gt;
}


/***********************************
Description: key generation algorithm of BLS scheme
Input: sysPara: public system parameter of blsSysPara type
Output: sk: secret key
	  PK: public key
***********************************/
void blsKGen(blsSysPara sysPara, Big &sk, G2 &PK)
{
	pfc.random(sk);					 // randomly choose sk as the secret key
	PK = pfc.mult(sysPara.g2, sk);   // compute g2^sk as the public key

}

/***********************************
Description: signing algorithm of BLS scheme
Input: sysPara: public system parameter of blsSysPara type
      sk: secret key
	  msg: message of BYTE type
Output: sig: signature of G1 type
***********************************/
void blsSign(blsSysPara sysPara, Big sk, BYTE * msg, G1 &sig)
{
	G1 tmp;
	pfc.hash_and_map(tmp, (char *)msg);
	sig = pfc.mult(tmp, sk);	// H(msg)^sk
}


/***********************************
Description: verification algorithm of BLS scheme
Input: sysPara: public system parameter of blsSysPara type
	  PK: public key of G2 type
	  msg: message of BYTE type
	  sig: signature of G1 type
Return: 0: if the signature is invalid
        1: otherwise
***********************************/
int blsVerf(blsSysPara sysPara, G2 PK, BYTE * msg, G1 sig)
{
	G1 H;
	GT ePS, eYH;
	pfc.hash_and_map(H, (char *)msg);
	pfc.precomp_for_pairing(PK);
	ePS = pfc.pairing(sysPara.g2, sig);    // e(g2, sig)
	eYH = pfc.pairing(PK, H);			   // e(PK, H(msg))
	if (ePS == eYH)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}