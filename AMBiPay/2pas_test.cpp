#include "2pas_test.h"
#include <ctime>
#include<windows.h>
#include <thread>

extern BYTE byte_g1[256];
extern BYTE byte_g2[640];
extern BYTE byte_gt[1920];
void NIZK_DL_test()
{

	time_t seed;

	Big p, a, b, xG, yG, n;
	ecdsaSysPara sysPara;
	nizkDLX st;
	nizkDLW wit;
	nizkDLPi pi;
	int t = 100;
	time(&seed);
	irand((long)seed);   /* change parameter for different values */

	int la = 256;
	// secp256k1 recommended by NIST - 256 bits security level
	BYTE *ecp = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	BYTE *eca = (BYTE *) "0000000000000000000000000000000000000000000000000000000000000000";
	BYTE *ecb = (BYTE *) "0000000000000000000000000000000000000000000000000000000000000007";
	BYTE *ecxG = (BYTE *) "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	BYTE *ecyG = (BYTE *) "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	BYTE *ecn = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	mip->IOBASE = 16;
	p = Big((char *)ecp);
	a = Big((char *)eca);
	b = Big((char *)ecb);
	n = Big((char *)ecn);
	xG = Big((char *)ecxG);
	yG = Big((char *)ecyG);
	
	ecdsaSetup(mip, sysPara, la, p, a, b, xG, yG, n);
	for(int i = 0; i < t; i ++)
	{		
		wit.w = rand(sysPara.n);
		st.Y = sysPara.G;
		st.Y *= wit.w;
		
		nizkProveDL(sysPara, st, wit, pi);
		if (nizkVerfDL(sysPara, st, pi))
		{
			cout << "True!\n" << endl;
		}
		else
		{
			cout << "Fail!\n" << endl;
			break;
		}
		
	}
	cout << "True!\n" << endl;

}


void ecdsa2Sign_test()
{
	Miracl precision(2050, 0);
	miracl *mip = &precision;
	LARGE_INTEGER freq;
	LARGE_INTEGER start_t, stop_t;
	double exe_time = 0;

	int num = 100;

	int secPara = 385;
	paiPubKey pk0;
	paiPriKey sk0;
	int factor = 3;
	
	Big p, a, b, xG, yG, n, BMod;
	Big d, d0, d1;
	ECn PK, PK0, PK1;
	ecdsaSysPara sysPara;
	int la = 256;
	int msgByteLen;
	ecdsaSig sigma, tmpsig;
	nizkDLX st0, st1;
	nizkDLW wi0, wi1;
	nizkDLPi pi0, pi1;
	Big cm0;
	Big d0cipher, cipher, d0plain;	
	Big y0, tmpy0;
	pSigma psig;
	Big cpart, cinvk;

	// secp256k1 recommended by NIST - 256 bits security level
	BYTE *ecp = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	BYTE *eca = (BYTE *) "0000000000000000000000000000000000000000000000000000000000000000";
	BYTE *ecb = (BYTE *) "0000000000000000000000000000000000000000000000000000000000000007";
	BYTE *ecxG = (BYTE *) "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	BYTE *ecyG = (BYTE *) "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	BYTE *ecn = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

	mip->IOBASE = 16;
	char* msg = (char *) "B09A20654ADEFAA07C80512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2D09A20654ADEFAA07C80512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A5";
	BYTE msgBYTE[MAXCHARSIZE];
	byteReset(msgBYTE, MAXCHARSIZE);
	charToByte(msg, strlen(msg), msgBYTE, msgByteLen);

	p = Big((char *)ecp);
	a = Big((char *)eca);
	b = Big((char *)ecb);
	xG = Big((char *)ecxG);
	yG = Big((char *)ecyG);
	n = Big((char *)ecn);
	ecdsaSetup(mip, sysPara, la, p, a, b, xG, yG, n);

	ecdsaKGen(mip, sysPara, factor, d0, PK0);
	ecdsaKGen(mip, sysPara, factor, d1, PK1);
	PK = PK0;
	PK *= d1;

	
	paillKGen(mip, secPara, pk0, sk0);
	paillEncMont(mip, pk0, d0, d0cipher);	
	modulo(sysPara.p);

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		P0Comit(sysPara, st0, wi0, pi0, cm0);
		P1Comit(sysPara, st1, wi1, pi1);
		P1Sign(sysPara, cm0, st0, pi0, d1, msgBYTE, msgByteLen, wi1, pk0, d0cipher, cipher);
		P0Sign(sysPara, st1, wi0, sk0, pk0, cipher, sigma);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Sign2 = " << exe_time / num << " ms" << endl;

	if (ecdsaVerf(mip, sysPara, PK, msgBYTE, msgByteLen, sigma))
	{
		cout << "Valid!" << endl;
	}
	else
	{
		cout << "sigma.r = " << sigma.r << endl;
		cout << "sigma.s = " << sigma.s << endl;
		cout << "Sign2 is invalid!" << endl;
	}

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		P0Comit(sysPara, st0, wi0, pi0, cm0);
		P1Comit(sysPara, st1, wi1, pi1);
		P1SignOffline(sysPara, cm0, st0, pi0, d1, wi1, pk0, d0cipher, cpart, cinvk);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Sign2Offline = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		P1SignOnline(sysPara, st0,  pi0, msgBYTE, msgByteLen, pk0, cpart,  cinvk,  cipher);
		P0Sign(sysPara, st1, wi0, sk0, pk0, cipher, sigma);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Sign2Online = " << exe_time / num << " ms" << endl;

	if (ecdsaVerf(mip, sysPara, PK, msgBYTE, msgByteLen, sigma))
	{
		cout << "Valid!" << endl;
	}
	else
	{
		cout << "sigma.r = " << sigma.r << endl;
		cout << "sigma.s = " << sigma.s << endl;
		cout << "Invalid!" << endl;
	}

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		ecdsaVerf(mip, sysPara, PK, msgBYTE, msgByteLen, sigma);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of ecdsaVerf = " << exe_time / num << " ms" << endl;


	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		y0 = rand(sysPara.n);
		pSignECDSA(sysPara, sigma, msgBYTE, msgByteLen, PK, y0, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of pSign2ECDSA = " << exe_time / num << " ms" << endl;
	
	if (pVerfECDSA(sysPara, PK, msgBYTE, msgByteLen, psig))
		cout << "Pre-signature is valid!" << endl;
	else
		cout << "Invalid!" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		y0 = rand(sysPara.n);
		pSignECDSAOffline(sysPara, wi0.w, st1.Y, PK, y0, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of pSignECDSAOffline = " << exe_time / num << " ms" << endl;
	
	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		pSignECDSAOnline(sysPara, sigma, y0, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of pSignECDSAOnline = " << exe_time / num << " ms" << endl;

	if (pVerfECDSA(sysPara, PK, msgBYTE, msgByteLen, psig))
		cout << "Pre-signature offline is valid!" << endl;
	else
		cout << "Invalid!" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		pVerfECDSA(sysPara, PK, msgBYTE, msgByteLen, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of pVerfECDSA = " << exe_time / num << " ms" << endl;
		

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		adaptECDSA(sysPara, psig, y0, tmpsig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of adaptECDSA = " << exe_time / num << " ms" << endl;

	adaptECDSA(sysPara, psig, y0, tmpsig);
	if (ecdsaVerf(mip, sysPara, PK, msgBYTE, msgByteLen, tmpsig))
	{
		cout << "Adapt correctly!" << endl;
	}
	else
		cout << "Incorrect!" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		extECDSA(sysPara, psig, sigma, tmpy0);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of extECDSA = " << exe_time / num << " ms" << endl;
	
	if(tmpy0 == y0)
		cout << "Extract correctly!" << endl;
	else
		cout << "Incorrect!" << endl;

	/*
	Big r, tmpg, tmp;
	ECn R;
	int ot = 1000;
	
	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < ot; k++)
	{
		r = rand(sysPara.n);
		QueryPerformanceCounter(&start_t);
		R = sysPara.G;
		R *= r;
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Tsm = " << exe_time / ot << " ms" << endl;

	cout << "pk0.N2 = " << pk0.N2 << endl;
	cout << "pk0.N = " << pk0.N << endl;
	cout << "pk0.g = " << pk0.g << endl;
	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < ot; k++)
	{
		r = rand(pk0.N2);
		tmpg = rand(pk0.N);
		tmp = tmpg * tmpg % pk0.N;
		tmpg = pk0.N - tmp;
		QueryPerformanceCounter(&start_t);
		modulo(pk0.N);		
		tmpg = nres(tmpg);
		tmp = nres_pow(tmpg,r);
		tmp = redc(tmp);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "tmp = " << tmp <<endl;
	cout << "The performance of TeN = " << exe_time / ot << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < ot; k++)
	{
		r = rand(pk0.N2);
		QueryPerformanceCounter(&start_t);
		modulo(pk0.N2);
		tmpg = nres(pk0.g);
		tmp = nres_pow(tmpg, r);
		tmp = redc(tmp);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "tmp = " << tmp << endl;
	cout << "The performance of TeN2 = " << exe_time / ot << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < ot; k++)
	{
		r = rand(pk0.N2);
		tmpg = rand(pk0.N2);
		QueryPerformanceCounter(&start_t);
		modulo(pk0.N2);
		r = nres(r);
		tmpg = nres(tmpg);
		tmp = nres_modmult(tmpg, r);
		tmp = redc(tmp);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "tmp = " << tmp << endl;
	cout << "The performance of TmN2 = " << exe_time / ot << " ms" << endl;
	*/
}

void bls2Sign_test()
{	
	
	LARGE_INTEGER freq;
	LARGE_INTEGER start_t, stop_t;
	double exe_time = 0;
	Big d0, d1, d;
	G2 P0, P1, P;
	int msgByteLen;
	blsSysPara sysPara;
	int num = 100;
	G1 sig0, sig1, sig, tmpsig;
	G1 y0, tmpy0;
	pSigma1 psig;
	
	char* msg = (char *) "B09A20654ADEFAA07C80512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2D09A20654ADEFAA07C80512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A5";
	BYTE msgBYTE[MAXCHARSIZE];
	byteReset(msgBYTE, MAXCHARSIZE);
	charToByte(msg, strlen(msg), msgBYTE, msgByteLen);
	
	blsSetup(byte_g1, byte_g2, byte_gt, sysPara);
	blsKGen(sysPara, d0, P0);
	blsKGen(sysPara, d1, P1);
	P = P0 + P1;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		blsSign(sysPara, d0, msgBYTE, sig0);
		blsSign(sysPara, d1, msgBYTE, sig1);
		sig = sig0 + sig1;
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Sign2BLS = " << exe_time / num << " ms" << endl;
	
	if (blsVerf(sysPara, P, msgBYTE, sig))
	{
		cout << "Signature is valid!" <<endl;
	}
	else
	{
		cout << "Signature is invalid!" << endl;
	}	
	
	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		blsVerf(sysPara, P, msgBYTE, sig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of blsVerf = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		pfc.random(y0);
		pSignBLS(sysPara, sig, msgBYTE, msgByteLen, y0, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of pSign2BLS = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		pfc.random(y0);
		pSignBLSOffline(sysPara, sig, msgBYTE, msgByteLen, y0, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of pSignBLSOffline = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		pSignBLSOnline(sysPara, sig, msgBYTE, msgByteLen, y0, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of pSignBLSOnline = " << exe_time / num << " ms" << endl;
	
	if (pVerfBLS(sysPara, msgBYTE, msgByteLen, P, psig))
	{
		cout << "Valid" << endl;
	}
	
	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		pVerfBLS(sysPara, msgBYTE, msgByteLen, P, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of pVerfBLS = " << exe_time / num << " ms" << endl;


	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		adaptBLS(sysPara, psig, y0, tmpsig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of adaptBLS = " << exe_time / num << " ms" << endl;
		
	if (tmpsig == sig)
	{
		cout << "Adapt correctly!" << endl;
	}

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		extBLS(sysPara, psig, sig, tmpy0);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of extBLS = " << exe_time / num << " ms" << endl;
	
	if (tmpy0 == y0)
	{
		cout << "Extract correctly!" << endl;
	}

}

void schnorr2Sign_test()
{
	LARGE_INTEGER freq;
	LARGE_INTEGER start_t, stop_t;
	double exe_time = 0;

	int num = 100;

	Big p, a, b, xG, yG, n, BMod;
	Big d, d0, d1;
	ECn PK, PK0, PK1;
	ECn R;
	ecdsaSysPara sysPara;
	int la = 256;
	int msgByteLen;
	schnorrSig sig, tmpsig, sig0, sig1;
	nizkDLX st0, st1;
	nizkDLW wi0, wi1;
	nizkDLPi pi0, pi1;
	Big cm0;
	Big y0, tmpy0;
	Big r;
	pSigSchnorr psig;
	// secp256k1 recommended by NIST
	BYTE *ecp = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	BYTE *eca = (BYTE *) "0000000000000000000000000000000000000000000000000000000000000000";
	BYTE *ecb = (BYTE *) "0000000000000000000000000000000000000000000000000000000000000007";
	BYTE *ecxG = (BYTE *) "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	BYTE *ecyG = (BYTE *) "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	BYTE *ecn = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

	mip->IOBASE = 16;
	char* msg = (char *) "B09A20654ADEFAA07C80512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2D09A20654ADEFAA07C80512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A5";
	BYTE msgBYTE[MAXCHARSIZE];
	byteReset(msgBYTE, MAXCHARSIZE);
	charToByte(msg, strlen(msg), msgBYTE, msgByteLen);
	
	p = Big((char *)ecp);
	a = Big((char *)eca);
	b = Big((char *)ecb);
	xG = Big((char *)ecxG);
	yG = Big((char *)ecyG);	
	n = Big((char *)ecn);
	ecdsaSetup(mip, sysPara, la, p, a, b, xG, yG, n);

	d0 = rand(sysPara.n);
	PK0 = sysPara.G;
	PK0 *= d0;

	d1 = rand(sysPara.n);
	PK1 = sysPara.G;
	PK1 *= d1;

	PK = PK0;
	PK += PK1;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		pfc.random(y0);
		P0Comit(sysPara, st0, wi0, pi0, cm0);
		P1Comit(sysPara, st1, wi1, pi1);
		R = st0.Y;
		R += st1.Y;
		signSchnorr(sysPara, R, wi0.w, d0, msgBYTE, msgByteLen, sig0);
		signSchnorr(sysPara, R, wi1.w, d1, msgBYTE, msgByteLen, sig1);
		sig.s = sig0.s + sig1.s;
		sig.R = R;
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of sign2Schnorr = " << exe_time / num << " ms" << endl;
	
	
	if (verfSchnorr(sysPara, PK, msgBYTE, msgByteLen, sig))
	{
		cout << "Valid!" << endl;
	}
	else
	{
		cout << "Signature is invalid!" << endl;
	}

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		P0Comit(sysPara, st0, wi0, pi0, cm0);
		P1Comit(sysPara, st1, wi1, pi1);
		R = st0.Y;
		R += st1.Y;
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of sign2SchnorrOffline = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		signSchnorr(sysPara, R, wi0.w, d0, msgBYTE, msgByteLen, sig0);
		signSchnorr(sysPara, R, wi1.w, d1, msgBYTE, msgByteLen, sig1);
		sig.s = sig0.s + sig1.s;
		sig.R = R;
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of sign2SchnorrOnline = " << exe_time / num << " ms" << endl;

	if (verfSchnorr(sysPara, PK, msgBYTE, msgByteLen, sig))
	{
		cout << "Valid!" << endl;
	}
	else
	{
		cout << "Online-signature is invalid!" << endl;
	}

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		verfSchnorr(sysPara, PK, msgBYTE, msgByteLen, sig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of verfSchnorr = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		y0 = rand(sysPara.n);
		psign2Schnorr(sysPara, PK, y0, msgBYTE, msgByteLen, sig, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of psign2Schnorr = " << exe_time / num << " ms" << endl;
	
	if (pverfSchnorr(sysPara, PK, msgBYTE, msgByteLen, sig, psig))
	{
		cout << "Pre-signature is valid!" << endl;
	}
	else
	{
		cout << "Pre-signature is invalid!" << endl;
	}

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		y0 = rand(sysPara.n);
		psign2SchnorrOffline(sysPara, y0, msgBYTE, msgByteLen, sig, psig); 
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of psign2SchnorrOffline = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);		
		psign2SchnorrOnline(sysPara, PK, y0, sig, psig); 
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of psign2SchnorrOnline = " << exe_time / num << " ms" << endl;

	if (pverfSchnorr(sysPara, PK, msgBYTE, msgByteLen, sig, psig))
	{
		cout << "Pre-signature is valid!" << endl;
	}
	else
	{
		cout << "Pre-signature is invalid!" << endl;
	}


	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		pverfSchnorr(sysPara, PK, msgBYTE, msgByteLen, sig, psig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of pverfSchnorr = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		adaptSchnorr(sysPara, psig, y0, tmpsig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of adaptSchnorr = " << exe_time / num << " ms" << endl;

	if (tmpsig.R == sig.R && tmpsig.s == sig.s)
	{
		cout << "Adapt correctly!" << endl;
	}

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		extSchnorr(sysPara, sig, psig, tmpy0);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of extSchnorr = " << exe_time / num << " ms" << endl;

	if(tmpy0 == y0)
	{
		cout << "Extract correctly!" << endl;
	}

	
}