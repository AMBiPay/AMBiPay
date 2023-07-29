#include "2pas.h"


/************************************
Description: proving algorithm of NIZK for DLOG
Input: sysPara: public system parameter
	   st: statement of nizkDLX type
	   wit: witness of nizkDLW type
	   
Return: pi: proof of nizkDLPi type
************************************/
void nizkProveDL(ecdsaSysPara sysPara, nizkDLX st, nizkDLW wit, nizkDLPi & pi)
{
	Big r, tmp;
	ECn R;
	Big Tmpx, Tmpy;

	mip->IOBASE = 16;

	r = rand(sysPara.n);
	R = sysPara.G;
	R *= r;			// commit R = rG

	pfc.start_hash();
	R.getxy(Tmpx, Tmpy);
	pfc.add_to_hash(Tmpx);
	pfc.add_to_hash(Tmpy);
	st.Y.getxy(Tmpx, Tmpy);
	pfc.add_to_hash(Tmpx);
	pfc.add_to_hash(Tmpy);
	sysPara.G.getxy(Tmpx, Tmpy);
	pfc.add_to_hash(Tmpx);
	pfc.add_to_hash(Tmpy);
	pi.e = pfc.finish_hash_to_group();

	tmp = modmult(wit.w, pi.e, sysPara.n);
	pi.z = (r - tmp + sysPara.n) % sysPara.n;

}

/************************************
Description: verication algorithm of NIZK for DLOG
Input: sysPara: public system parameter
	   st: statement of nizkDLX type
	   pi: proof of nizkDLPi type

Return: 1 if proof is true, or 0 otherwise
************************************/
int nizkVerfDL(ecdsaSysPara sysPara, nizkDLX st, nizkDLPi pi)
{
	Big tmpe;
	ECn tmpR, tmpZ;
	Big Tmpx, Tmpy;

	mip->IOBASE = 16;

	tmpR = st.Y;
	tmpR *= pi.e;			
	tmpZ = sysPara.G;
	tmpZ *= pi.z;
	tmpR += tmpZ;  // compute tmpR = zG + eY


	pfc.start_hash();
	tmpR.getxy(Tmpx, Tmpy);
	pfc.add_to_hash(Tmpx);
	pfc.add_to_hash(Tmpy);
	st.Y.getxy(Tmpx, Tmpy);
	pfc.add_to_hash(Tmpx);
	pfc.add_to_hash(Tmpy);
	sysPara.G.getxy(Tmpx, Tmpy);
	pfc.add_to_hash(Tmpx);
	pfc.add_to_hash(Tmpy);
	tmpe = pfc.finish_hash_to_group();


	if (tmpe == pi.e)
	{
		return 1;
	}
	else
	{
		cout << "tmpe = " << tmpe << endl;
		cout << "pi.e = " << pi.e << endl;
		return 0;
	}

}

/************************************
Description: party P0's commit algorithm of 2-p ECDSA in CRYPTO 2017
Input: sysPara: public system parameter	   

Return: st0: statement of nizkDLX type
		wi0: witness of nizkDLW type
	    pi0: proof of nizkDLPi type
		cm0: commitment of st and pi
************************************/

void P0Comit(ecdsaSysPara sysPara, nizkDLX &st0, nizkDLW &wi0, nizkDLPi &pi0, Big &cm0)
{
	Big Tmpx, Tmpy;
	mip->IOBASE = 16;

	wi0.w = rand(sysPara.n);

	st0.Y = sysPara.G;
	st0.Y *= wi0.w;

	nizkProveDL(sysPara, st0, wi0, pi0);

	pfc.start_hash();
	st0.Y.getxy(Tmpx, Tmpy);
	pfc.add_to_hash(Tmpx);
	pfc.add_to_hash(Tmpy);

	pfc.add_to_hash(pi0.e);
	pfc.add_to_hash(pi0.z);

	cm0 = pfc.finish_hash_to_group();

}

/************************************
Description: party P1 commit algorithm of 2-p ECDSA in CRYPTO 2017
Input: sysPara: public system parameter

Return: st1: statement of nizkDLX type
		wi1: witness of nizkDLW type
		pi1: proof of nizkDLPi type
************************************/
void P1Comit(ecdsaSysPara sysPara, nizkDLX &st1, nizkDLW &wi1, nizkDLPi &pi1)
{
	Big Tmpx, Tmpy;
	mip->IOBASE = 16;

	wi1.w = rand(sysPara.n);

	st1.Y = sysPara.G;
	st1.Y *= wi1.w;

	nizkProveDL(sysPara, st1, wi1, pi1);
		
}

/************************************
Description: party P1's signing algorithm of 2-p ECDSA in CRYPTO 2017
Input: sysPara: public system parameter
	   cm0: P0's decommitment
	   st0: statement of nizkDLX type		
	   pi0: proof of nizkDLPi type
	   d1: part secret key
	   msg: message
	   msgByteLen: message byte length
	   wi1: P1's randomly chosen randomness
	   pk0: P0's paillier public key
	   d0cipher: P0's key ciphertext upon pk0

Return:  cipher: ciphertext of part signature if P0's decommitment is true
		 0: otherwise		
************************************/
int P1Sign(ecdsaSysPara sysPara, Big cm0, nizkDLX st0, nizkDLPi pi0, Big d1, BYTE *msg, int msgByteLen, nizkDLW wi1, paiPubKey pk0, Big d0cipher, Big &cipher)
{
	Big Tmpx, Tmpy;
	Big Tmpcm0;
	Big e, rho, invk1, r, tmp, tmp1, tmp2, tmp3, tmpcipher, dcipher, BMod;
	ECn R;
	Big x, y;

	pfc.start_hash();
	st0.Y.getxy(Tmpx, Tmpy);
	pfc.add_to_hash(Tmpx);
	pfc.add_to_hash(Tmpy);

	pfc.add_to_hash(pi0.e);
	pfc.add_to_hash(pi0.z);

	Tmpcm0 = pfc.finish_hash_to_group();

	if ((Tmpcm0 != cm0) || (!nizkVerfDL(sysPara, st0, pi0)))  // check the commitment and the DL proof
	{
		return 0;
	}

	R = st0.Y;
	R *= wi1.w;

	R.getxy(x, y);
	r = x % sysPara.n;

	Hash(msg, e);  // hash value of message

	rho = rand(sysPara.n * sysPara.n);
	tmp1 = rho * sysPara.n;

	invk1 = inverse(wi1.w, sysPara.n);	 
	tmp = modmult(invk1, e, sysPara.n);
	tmp2 = tmp + tmp1;                  // tmp2 = invk1 * H(msg) + rho*n

	paillEncMont(mip, pk0, tmp2, tmpcipher);
	modulo(sysPara.p);

	tmp = modmult(invk1, r, sysPara.n);
	tmp1 = modmult(tmp, d1, sysPara.n);  // tmp1 =  invk1 * r * d1

	
	modulo(pk0.N2);
	d0cipher = nres(d0cipher);
	tmpcipher = nres(tmpcipher);   

	tmp2 = nres_pow(d0cipher, tmp1);
	tmp3 = nres_modmult(tmp2, tmpcipher);  // the ciphertext of invk1*r*d1*d2 + invk1 * H(msg) + rho*n
	cipher = redc(tmp3);

	modulo(sysPara.p);
	return 1;

}

/************************************
Description: party P1's offline signing algorithm of 2-p ECDSA in CRYPTO 2017
Input: sysPara: public system parameter
	   cm0: P0's decommitment
	   st0: statement of nizkDLX type
	   pi0: proof of nizkDLPi type
	   d1: part secret key
	   wi1: P1's randomly chosen randomness
	   pk0: P0's paillier public key
	   d0cipher: P0's key ciphertext upon pk0

Return:  cpart: part ciphertext of part signature if P0's decommitment is true
		 cinvk: ciphertext of the inverse k
		 0: otherwise
************************************/
int P1SignOffline(ecdsaSysPara sysPara, Big cm0, nizkDLX st0, nizkDLPi pi0, Big d1, nizkDLW wi1, paiPubKey pk0, Big d0cipher, Big &cpart, Big &cinvk)
{
	Big Tmpx, Tmpy;
	Big Tmpcm0;
	Big rho, invk1, r, tmp, tmp1, tmp2;
	ECn R;
	Big x, y, krx;
	Big krdcipher, crhoq;

	pfc.start_hash();
	st0.Y.getxy(Tmpx, Tmpy);
	pfc.add_to_hash(Tmpx);
	pfc.add_to_hash(Tmpy);

	pfc.add_to_hash(pi0.e);
	pfc.add_to_hash(pi0.z);

	Tmpcm0 = pfc.finish_hash_to_group();

	if ((Tmpcm0 != cm0) || (!nizkVerfDL(sysPara, st0, pi0)))
	{
		return 0;
	}

	R = st0.Y;
	R *= wi1.w;

	R.getxy(x, y);
	r = x % sysPara.n;

	invk1 = inverse(wi1.w, sysPara.n);
	paillEncMont(mip, pk0, invk1, cinvk);
	modulo(sysPara.p);

	tmp = modmult(invk1, r, sysPara.n);
	krx = modmult(tmp, d1, sysPara.n);    // krx = invk1 * r * d1 % n

	rho = rand(sysPara.n * sysPara.n);
	tmp = rho * sysPara.n;
	paillEncMont(mip, pk0, tmp, crhoq);

	modulo(pk0.N2);
	d0cipher = nres(d0cipher);
	crhoq = nres(crhoq);
	krdcipher = nres_pow(d0cipher, krx);
	tmp2 = nres_modmult(crhoq, krdcipher);
	cpart = redc(tmp2);
	
	modulo(sysPara.p);

	return 1;

}
/************************************
Description: party P1's online signing algorithm of 2-p ECDSA in CRYPTO 2017
Input: sysPara: public system parameter
	   st0: statement of nizkDLX type
	   pi0: proof of nizkDLPi type
	   msg: message
	   msgByteLen: the byte length of message
	   pk0: P0's paillier public key
	   cpart: part ciphertext of part signature
	   cinvk: ciphertext of the inverse k

Return:  cipher: ciphertext of part signature if P0's decommitment is true
		 0: otherwise
************************************/
int P1SignOnline(ecdsaSysPara sysPara, nizkDLX st0, nizkDLPi pi0, BYTE *msg, int msgByteLen, paiPubKey pk0, Big cpart, Big  cinvk, Big &cipher)
{
	Big e, tmp, tmp1, tmp2, tmp3, tmp4;

	Hash(msg, e);  // hash value of message

	modulo(pk0.N2);
	cinvk = nres(cinvk);
	cpart = nres(cpart);
	cipher = nres_pow(cinvk, e);
	tmp = nres_modmult(cipher, cpart);
	cipher = redc(tmp);
	modulo(sysPara.p);
	return 1;

}

/************************************
Description: party P0's signing algorithm of 2-p ECDSA in CRYPTO 2017
Input: sysPara: public system parameter
	   st1: statement of nizkDLX type
	   wi0: witness of nizkDLPi type
	   sk0: P0's paillier secret key
	   pk0: P0's paillier public key
	   cipher: ciphertext of part signature

Return:  sigma: the final signature
************************************/

void P0Sign(ecdsaSysPara sysPara, nizkDLX st1, nizkDLW wi0, paiPriKey sk0, paiPubKey pk0, Big cipher, ecdsaSig &sigma)
{
	ECn R;
	Big invk0, x, y, tmps;

	R = st1.Y;
	R *= wi0.w;

	R.getxy(x, y);
	sigma.r = x % sysPara.n;

	paillDecMont(mip, sk0, pk0, cipher, tmps);
	modulo(sysPara.p);

	invk0 = inverse(wi0.w, sysPara.n);
	sigma.s = modmult(invk0, tmps, sysPara.n);

}

/************************************
Description: the pre-signing algorithm of 2-party ECDSA adaptor signature scheme 
Input: sysPara: public system parameter
	   sigma: the 2-party signature
	   msg: message
	   msgByteLen: the byte length of message
	   P: the public key
	   y0: witness of nizkDLPi type
	   
Return:  psig: the final pre-signature
************************************/
void pSignECDSA(ecdsaSysPara sysPara, ecdsaSig sigma, BYTE *msg, int msgByteLen, ECn P, Big y0, pSigma &psig)
{
	Big invy0, invs, e, tmph, tmpr;
	Big r0, z0, e0, tmpx, tmpy;
	ECn K, tmpP, tmpK, R0;


	invy0 = inverse(y0, sysPara.n);
	psig.ws = modmult(invy0, sigma.s, sysPara.n);

	invs = inverse(sigma.s, sysPara.n);
	Hash(msg, e);  // hash value of message
	
	tmph = modmult(invs, e, sysPara.n);
	tmpr = modmult(invs, sigma.r, sysPara.n);
	K = sysPara.G;
	K *= tmph;
	tmpP = P;
	tmpP *= tmpr;
	K += tmpP;

	tmpK.set(sigma.r, 1);
	if (K == tmpK)
	{
		psig.b = 1;
	}
	else
	{
		psig.b = 0;
	}

	psig.r = sigma.r;

	psig.Y0 = K;
	psig.Y0 *= y0;

	r0 = rand(sysPara.n);
	R0 = K;
	R0 *= r0;

	pfc.start_hash();
	R0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	psig.Y0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	K.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);	

	psig.e0 = pfc.finish_hash_to_group();

	tmph = modmult(psig.e0, y0, sysPara.n);
	psig.z0 = (r0 + sysPara.n - tmph) % sysPara.n;
}
/************************************
Description: the offline pre-signing algorithm of 2-party ECDSA adaptor signature scheme
Input: sysPara: public system parameter
	   k0: random chosen by P0
	   K1: committed point decided by both parties
	   P: the public key
	   y0: witness of nizkDLPi type

Return:  psig: the final pre-signature
************************************/
void pSignECDSAOffline(ecdsaSysPara sysPara, Big k0, ECn K1, ECn P, Big y0, pSigma &psig)
{
	Big e, tmph, tmpr;
	Big r0, tmpx, tmpy;
	ECn K, R0;

	K = K1;
	K *= k0;
	
	psig.Y0 = K;
	psig.Y0 *= y0;

	r0 = rand(sysPara.n);
	R0 = K;
	R0 *= r0;

	pfc.start_hash();
	R0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	psig.Y0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	K.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	psig.e0 = pfc.finish_hash_to_group();

	tmph = modmult(psig.e0, y0, sysPara.n);
	psig.z0 = (r0 + sysPara.n - tmph) % sysPara.n;
}

/************************************
Description: the online pre-signing algorithm of 2-party ECDSA adaptor signature scheme
Input: sysPara: public system parameter
	   simga: 2-party signature
	   y0: witness of nizkDLPi type

Return:  psig: the final pre-signature
************************************/
void pSignECDSAOnline(ecdsaSysPara sysPara, ecdsaSig sigma, Big y0, pSigma &psig)
{
	Big invy0;

	invy0 = inverse(y0, sysPara.n);
	psig.ws = modmult(invy0, sigma.s, sysPara.n);
	psig.r = sigma.r;

}

/************************************
Description: the verification algorithm for pre-signatures in 2-party ECDSA adaptor signature scheme
Input: sysPara: public system parameter
	   P: public key
	   msg: message
	   msgByteLen: the byte length of message
	   psig: the pre-signature

Return:  1: the pre-signature is valid
		 0: invalid otherwise
************************************/
int pVerfECDSA(ecdsaSysPara sysPara, ECn P, BYTE *msg, int msgByteLen, pSigma psig)
{
	Big tmpe0, tmpx, tmpy;
	ECn K, tmpR0, tmpY0, tmpP;
	Big invs, e, tmph, tmpr;

	K.set(psig.r, psig.b);
	
	tmpR0 = K;
	tmpR0 *= psig.z0;
	tmpY0 = psig.Y0;
	tmpY0 *= psig.e0;
	tmpR0 += tmpY0;

	pfc.start_hash();
	tmpR0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	psig.Y0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	K.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	tmpe0 = pfc.finish_hash_to_group();	

	if (tmpe0 != psig.e0)
	{
		cout << "Fail to recover R!" << endl;
		return 0;
	}

	invs = inverse(psig.ws, sysPara.n);
	Hash(msg, e);  // hash value of message

	tmph = modmult(invs, e, sysPara.n);
	tmpr = modmult(invs, psig.r, sysPara.n);
	tmpY0 = sysPara.G;
	tmpY0 *= tmph;
	tmpP = P;
	tmpP *= tmpr;
	tmpY0 += tmpP;
	if (tmpY0 != psig.Y0)
	{
		return 0;
	}
	else
	{
		return 1;
	}

}

void adaptECDSA(ecdsaSysPara sysPara, pSigma psig, Big y0, ecdsaSig &sig)
{
	sig.r = psig.r;
	sig.s = modmult(psig.ws, y0, sysPara.n);
}

void extECDSA(ecdsaSysPara sysPara, pSigma psig, ecdsaSig sig, Big &y0)
{
	Big invs;

	invs = inverse(psig.ws, sysPara.n);
	y0 = modmult(sig.s, invs, sysPara.n);
}

void signSchnorr(ecdsaSysPara sysPara, ECn R, Big r, Big d, BYTE *msg, int msgByteLen, schnorrSig &sig)
{
	Big e, Bmsg, tmpx, tmpy;
	Bmsg = from_binary(PFC_BYTELEN_PER_BIG, (char *)msg);
	pfc.start_hash();
	pfc.add_to_hash(Bmsg);
	R.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	sysPara.G.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	e = pfc.finish_hash_to_group();

	sig.R = R;
	sig.s = modmult(e, d, sysPara.n);
	sig.s = (r - sig.s + sysPara.n) % sysPara.n;
}

int verfSchnorr(ecdsaSysPara sysPara, ECn P, BYTE *msg, int msgByteLen, schnorrSig sig)
{
	ECn tmpR, tmpP;
	Big tmpe, Bmsg, tmpx, tmpy;

	Bmsg = from_binary(PFC_BYTELEN_PER_BIG, (char *)msg);
	pfc.start_hash();
	pfc.add_to_hash(Bmsg);
	sig.R.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	sysPara.G.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	tmpe = pfc.finish_hash_to_group();
	
	tmpR = sysPara.G;
	tmpR *= sig.s;
	tmpP = P;
	tmpP *= tmpe;
	tmpR += tmpP;
	
	if (sig.R == tmpR)
	{
		return 1;
	}
	else
	{
		return 0;
	}

}

void psign2Schnorr(ecdsaSysPara sysPara, ECn P, Big y0, BYTE *msg, int msgByteLen, schnorrSig sig, pSigSchnorr &psig)
{
	Big r0, e0, tmpx, tmpy;
	ECn R0;
	psig.R = sig.R;
	psig.ws = (sig.s + y0) % sysPara.n;
	psig.Y0 = sysPara.G;
	psig.Y0 *= y0;

	r0 = rand(sysPara.n);
	R0 = sysPara.G;
	R0 *= r0;

	pfc.start_hash();
	R0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	psig.Y0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	sysPara.G.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	psig.e0 = pfc.finish_hash_to_group();

	tmpy = modmult(psig.e0, y0, sysPara.n);
	psig.z0 = (r0 - tmpy + sysPara.n) % sysPara.n;
}

void psign2SchnorrOnline(ecdsaSysPara sysPara, ECn P, Big y0, schnorrSig sig, pSigSchnorr &psig)
{
	psig.R = sig.R;
	psig.ws = (sig.s + y0) % sysPara.n;
}

void psign2SchnorrOffline(ecdsaSysPara sysPara, Big y0, BYTE *msg, int msgByteLen, schnorrSig sig, pSigSchnorr &psig)
{
	Big r0, tmpx, tmpy;
	ECn R0;

	psig.Y0 = sysPara.G;
	psig.Y0 *= y0;

	r0 = rand(sysPara.n);
	R0 = sysPara.G;
	R0 *= r0;

	pfc.start_hash();
	R0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	psig.Y0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	sysPara.G.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	psig.e0 = pfc.finish_hash_to_group();

	tmpy = modmult(psig.e0, y0, sysPara.n);
	psig.z0 = (r0 - tmpy + sysPara.n) % sysPara.n;
}


int pverfSchnorr(ecdsaSysPara sysPara, ECn P, BYTE *msg, int msgByteLen, schnorrSig sig, pSigSchnorr psig)
{
	ECn tmpR0, tmpZ0, tmpY0, tmpP, tmpR;
	Big tmpe0, tmpx, tmpy, Bmsg;

	tmpR0 = sysPara.G;
	tmpR0 *= psig.z0;
	tmpY0 = psig.Y0;
	tmpY0 *= psig.e0;
	tmpR0 += tmpY0;

	pfc.start_hash();
	tmpR0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	psig.Y0.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	sysPara.G.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	tmpe0 = pfc.finish_hash_to_group();
	

	if (tmpe0 != psig.e0)
	{
		cout << "Fail to recover R0" << endl;
		return 0;
	}

	Bmsg = from_binary(PFC_BYTELEN_PER_BIG, (char *)msg);
	pfc.start_hash();
	pfc.add_to_hash(Bmsg);
	psig.R.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	sysPara.G.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	tmpe0 = pfc.finish_hash_to_group();
	
	tmpP = P;
	tmpP *= tmpe0;
	tmpY0 = sysPara.G;
	tmpY0 *= psig.ws;
	tmpY0 += tmpP;
	tmpR = -psig.R;
	tmpY0 += tmpR;
	if (tmpY0 != psig.Y0)
	{
		cout << "Fail to recover Y0" << endl;
		return 0;
	}
	else
	{
		return 1;
	}
}

void adaptSchnorr(ecdsaSysPara sysPara, pSigSchnorr psig, Big y0, schnorrSig &sig)
{
	sig.R = psig.R;
	sig.s = (psig.ws - y0 + sysPara.n) % sysPara.n;
}

void extSchnorr(ecdsaSysPara sysPara, schnorrSig sig, pSigSchnorr psig, Big &y0)
{
	y0 = (psig.ws - sig.s + sysPara.n) % sysPara.n;
}

void pSignBLS(blsSysPara sysPara, G1 sigma, BYTE *msg, int msgByteLen, G1 y0, pSigma1 &psig)
{
	G1 r0, tmpG1;
	Big e0;
	GT R0;
	
	psig.ws = sigma + y0;
	pfc.precomp_for_pairing(sysPara.g2);
	psig.Y0 = pfc.pairing(sysPara.g2, y0);
	pfc.random(r0);

	R0 = pfc.pairing(sysPara.g2, r0);
	pfc.start_hash();
	pfc.add_to_hash(R0);
	pfc.add_to_hash(psig.Y0);
	pfc.add_to_hash(sysPara.g1);
	pfc.add_to_hash(sysPara.g2);
	pfc.add_to_hash(sysPara.gt);
	psig.e0 = pfc.finish_hash_to_group();

	tmpG1 = pfc.mult(y0, pfc.order() - psig.e0);
	psig.z0 = r0 + tmpG1;
}

void pSignBLSOnline(blsSysPara sysPara, G1 sigma, BYTE *msg, int msgByteLen, G1 y0, pSigma1 &psig)
{
	G1 r0, tmpG1;
	Big e0;

	psig.ws = sigma + y0;
}

void pSignBLSOffline(blsSysPara sysPara, G1 sigma, BYTE *msg, int msgByteLen, G1 y0, pSigma1 &psig)
{
	G1 r0, tmpG1;
	Big e0;
	GT R0;

	psig.ws = sigma + y0;
	pfc.precomp_for_pairing(sysPara.g2);
	psig.Y0 = pfc.pairing(sysPara.g2, y0);
	pfc.random(r0);

	R0 = pfc.pairing(sysPara.g2, r0);
	pfc.start_hash();
	pfc.add_to_hash(R0);
	pfc.add_to_hash(psig.Y0);
	pfc.add_to_hash(sysPara.g1);
	pfc.add_to_hash(sysPara.g2);
	pfc.add_to_hash(sysPara.gt);
	psig.e0 = pfc.finish_hash_to_group();

	tmpG1 = pfc.mult(y0, pfc.order() - psig.e0);
	psig.z0 = r0 + tmpG1;
}

int pVerfBLS(blsSysPara sysPara, BYTE *msg, int msgByteLen, G2 P, pSigma1 psig)
{
	GT tmpR0, tmpY0, tmpP;
	G1 HMsg;
	Big tmpe0;
	
	pfc.precomp_for_pairing(sysPara.g2);
	pfc.precomp_for_pairing(P);
	tmpR0 = pfc.pairing(sysPara.g2, psig.z0);
	tmpY0 = pfc.power(psig.Y0, tmpe0);
	tmpR0 = tmpR0 * tmpY0;

	pfc.start_hash();
	pfc.add_to_hash(tmpR0);
	pfc.add_to_hash(psig.Y0);
	pfc.add_to_hash(sysPara.g1);
	pfc.add_to_hash(sysPara.g2);
	pfc.add_to_hash(sysPara.gt);
	tmpe0 = pfc.finish_hash_to_group();

	
	if (tmpe0 != psig.e0)
	{
		cout << "Fail to recover R0!" <<endl;
		return 0;
	}
		
	tmpY0 = pfc.pairing(sysPara.g2, psig.ws);
	pfc.hash_and_map(HMsg, (char *)msg);
	tmpP = pfc.pairing(P, HMsg);
	tmpY0 = tmpY0 / tmpP;
	if (tmpY0 != psig.Y0)
	{
		cout << "Fail to recover Y0!" << endl;
		return 0;
	}
	else
	{
		return 1;
	}

}

void adaptBLS(blsSysPara sysPara, pSigma1 psig, G1 y0, G1 &sigma)
{
	G1 invy0;
	invy0 = -y0;
	sigma = psig.ws + invy0;
}

void extBLS(blsSysPara sysPara, pSigma1 psig, G1 sigma, G1 &y0)
{
	G1 invs;
	invs = -sigma;
	y0 = psig.ws + invs;
}

