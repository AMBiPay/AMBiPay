#include "ecdsa.h"


/***********************************
Description: hash function
Input: input: BYTE array
Ouput: hash value of Big type
***********************************/
void Hash(BYTE *input, Big &h)

{
	BYTE s[VBYTELEN] = { 0 };
	sha sh;
	shs_init(&sh);
	int i = 0;
	while (input[i] != '\0')
	{
		shs_process(&sh, input[i]);
		i++;
	}
	shs_hash(&sh, (char *)s);

	h = from_binary(VBYTELEN, (char *)s);
}

/************************************
Description: setup algorithm of ECDSA
Input: mip: the variable of miracl library
      la: secure parameter
	  p: element of field Fp
	  a: coefficient of y^2=x^3+ax+b
	  b: coefficient of y^2=x^3+ax+b
	  xG: x-coordinate of additive group G
	  yG: y-coordinate of additive group G
	  n: order of additive group G
Output: sysPara: public system parameter
Return: 1: if setup successfully
		0: otherwise
*************************************/
int ecdsaSetup(miracl *mip, ecdsaSysPara &sysPara, int la, Big p, Big a, Big b, Big xG, Big yG, Big n)
{
	ECn tmpG;
	sysPara.la = la;
	sysPara.p = p;
	sysPara.a = a;
	sysPara.b = b;
	mip->IOBASE = 16;
	ecurve(a, b, p, MR_AFFINE);    // init the curve
	if (!sysPara.G.set(xG, yG))
	{
		cout << "The (xG, yG) is not a generator!" << endl;
		return 0;
	}
	tmpG = sysPara.G;
	tmpG *= n;
	if (!tmpG.iszero())           // check the generator 
	{
		cout << "The order is of the group is not n!" << endl;
		return 0;
	}
	else
	{
		sysPara.n = n;
		return 1;
	}
}

/************************************
Description: key generation algorithm of ECDSA
Input: mip: the variable of miracl library
	   sysPara: public system parameter
Output: sk: secret key of Big type
		PK: public key of ECn type
Return: 1: if generate key-pair successfully
		0: otherwise
************************************/
int ecdsaKGen(miracl *mip, ecdsaSysPara sysPara, Big &sk, ECn &PK)
{
	mip->IOBASE = 16;
	sk = rand(sysPara.n);
	PK = sysPara.G;
	PK *= sk;			// PK = skG
	if (PK.iszero())
	{
		cout << "Wrong secret key!" << endl;
		return 0;
	}
	return 1;

}

/************************************
Description: key generation algorithm of ECDSA
Input: mip: the variable of miracl library
	   sysPara: public system parameter
	   factor: reduction factor for 2-party ECDSA
Output: sk: secret key of Big type
		PK: public key of ECn type
Return: 1: if generate key-pair successfully
		0: otherwise
************************************/
int ecdsaKGen(miracl *mip, ecdsaSysPara sysPara, int factor, Big &sk, ECn &PK)
{
	mip->IOBASE = 16;
	sk = rand(sysPara.n/factor);
	PK = sysPara.G;
	PK *= sk;			// PK = skG
	if (PK.iszero())
	{
		cout << "Wrong secret key!" << endl;
		return 0;
	}
	return 1;

}


/************************************
Description: signing algorithm of ECDSA
Input: mip: the variable of miracl library
	   sysPara: public system parameter
	   sk: secret key of Big type
	   msg: message of BYTE type
	   msgByteLen: byte length of msg
Output: ecdsaSig: ECDSA signature
Return: 1: if sign the message successfully
		0: otherwise
************************************/
int ecdsaSign(miracl *mip, ecdsaSysPara sysPara, Big sk, BYTE *msg, int msgByteLen, ecdsaSig &ecdsaSig)
{
	Big e;
	Big k;
	Big invk;
	ECn K;
	Big xK, yK;
	Big tmp;
	mip->IOBASE = 16;

	Hash(msg, e);

	k = rand(sysPara.n);
	K = sysPara.G;
	K *= k;				           // K = k G

	K.getxy(xK, yK);			   // K = (xK, yK)
	ecdsaSig.r = xK % sysPara.n;   // r = xK mod n
	if (ecdsaSig.r == 0)
	{
		cout << "Signature Fails" << endl;
		return 0;
	}
	invk = inverse(k, sysPara.n);				// invk = k^{-1} mod n
	tmp = ecdsaSig.r*sk  % sysPara.n;	 
	ecdsaSig.s = (invk *(e + tmp)) % sysPara.n; // s = invk*(H(msg)+r*sk) mod n
	
	if (ecdsaSig.s == 0)
	{
		cout << "Signature Fails" << endl;
		return 0;
	}
	return 1;
}

/************************************
Description: verification algorithm of ECDSA
Input: mip: the variable of miracl library
	   sysPara: public system parameter
	   PK: public key of ECn type
	   msg: message of BYTE type
	   msgByteLen: byte length of msg
	   ecdsaSig: ECDSA signature
Return: 1: if the signature is valid
		0: otherwise
************************************/
int ecdsaVerf(miracl *mip, ecdsaSysPara sysPara, ECn PK, BYTE *msg, int msgByteLen, ecdsaSig ecdsaSig)
{
	Big e;
	Big u1, u2;
	ECn K, tmpG, tmpPK;
	Big invs;
	Big xK, yK;
	mip->IOBASE = 16;

	Hash(msg, e);
	
	invs = inverse(ecdsaSig.s, sysPara.n);		// invs = s^{-1} mod n
	u1 = (invs * e) % sysPara.n;				// u1 = invs * H(msg) mod n
	u2 = (invs * ecdsaSig.r) % sysPara.n;	    // u2 = invs * r mod n

	tmpG = sysPara.G;
	tmpG *= u1;

	tmpPK = PK;
	tmpPK *= u2;

	K = tmpG;
	K += tmpPK;

	//K = mul(u1, sysPara.G, u2, PK);				// K = u1 G + u2 PK
	
	K.getxy(xK, yK);							// K = (xK, yK)
	xK %= sysPara.n;							// xK = xK mod n
	if (ecdsaSig.r == xK)						// if r = xK, then returns 1 to show that the signature is valid
	{
		return 1;
	}
	else
	{
		return 0;
	}
	
}

/************************************
Description: verification algorithm of ECDSA uising BLS parameter
Input: mip: the variable of miracl library
	   sysPara: public system parameter of BLS signature
	   PK: public key of G1 type
	   msg: message of BYTE type
	   msgByteLen: byte length of msg
	   ecdsaSig: ECDSA signature
Return: 1: if the signature is valid
		0: otherwise
************************************/
int ecdsaVerf(miracl *mip, blsSysPara sysPara, G1 PK, BYTE *msg, int msgByteLen, ecdsaSig ecdsaSig)
{
	Big e;
	Big u1, u2;
	G1 K, tmpG, tmpPK;
	Big invs;
	Big xK, yK;
	mip->IOBASE = 16;

	Hash(msg, e);

	invs = inverse(ecdsaSig.s, pfc.order());		// invs = s^{-1} mod n
	u1 = (invs * e) % pfc.order();				// u1 = invs * H(msg) mod n
	u2 = (invs * ecdsaSig.r) % pfc.order();	    // u2 = invs * r mod n

	tmpG = pfc.mult(sysPara.g1, u1);

	tmpG = pfc.mult(PK, u2);
	

	K.g.getxy(xK, yK);

	xK %= pfc.order();							// xK = xK mod n
	if (ecdsaSig.r == xK)						// if r = xK, then returns 1 to show that the signature is valid
	{
		return 1;
	}
	else
	{
		return 0;
	}

}