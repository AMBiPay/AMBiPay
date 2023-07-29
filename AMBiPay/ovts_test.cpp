#include "ovts_test.h"
using namespace std;
#include <ctime>
#include<windows.h>

void CommitProve_test()
{
	LARGE_INTEGER freq;
	LARGE_INTEGER start_t, stop_t;
	double exe_time = 0;
	int num = 100;
	Big p, a, b, xG, yG, n;
	
	ecdsaSysPara sysPara;
	int la = 256, msgByteLen;
	
	BYTE *ecp = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	BYTE *eca = (BYTE *) "0000000000000000000000000000000000000000000000000000000000000000";
	BYTE *ecb = (BYTE *) "0000000000000000000000000000000000000000000000000000000000000007";
	BYTE *ecxG = (BYTE *) "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	BYTE *ecyG = (BYTE *) "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	BYTE *ecn = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	/*
	BYTE *ecp = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	BYTE *eca = (BYTE *) "00";
	BYTE *ecb = (BYTE *) "07";
	BYTE *ecxG = (BYTE *) "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	BYTE *ecyG = (BYTE *) "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
	BYTE *ecn = (BYTE *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	*/
	mip->IOBASE = 16;
	p = Big((char *)ecp);
	a = Big((char *)eca);
	b = Big((char *)ecb);
	xG = Big((char *)ecxG);
	yG = Big((char *)ecyG);
	n = Big((char *)ecn);
	char* msg = (char *) "B09A20654ADEFAA07C80512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2D09A20654ADEFAA07C80512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A5";
	BYTE msgBYTE[MAXCHARSIZE];
	byteReset(msgBYTE, MAXCHARSIZE);
	charToByte(msg, strlen(msg), msgBYTE, msgByteLen);
	ecdsaSig sig;
	Big esk;
	ECn ePK, TMP;
	ovtsSysPara opara;
	paiPubKey ppk;
	paiPriKey psk;
	ovtsX ox;
	ovtsW ow;
	ovtsPi opi;
	int tau = 100;
	Big tmp, tmpg, tmpe, BMod;

	ecdsaSetup(mip, sysPara, la, p, a, b, xG, yG, n);
	ecdsaKGen(mip, sysPara, esk, ePK);
	ecdsaSign(mip, sysPara, esk, msgBYTE, msgByteLen, sig);
	paillKGen(mip, 2*la, ppk, psk);
	opara.G = sysPara.G;
	opara.q = sysPara.n;
	opara.n = ppk.N;
	opara.n2 = ppk.N2;
	
	tmpg = rand(ppk.N);
	opara.g = (opara.n - tmpg * tmpg % opara.n);	

	BMod = get_modulus();
	tmpe = pow(Big(2), tau, psk.lambda / 2);
	opara.h = pow(opara.g, tmpe, ppk.N);
	modulo(BMod);

		
	tmp = rand(opara.q);
	ox.xG2 = opara.G;
	ox.xG2 *= tmp;
	TMP = ox.xG2;
	TMP *= opara.q;


	tmp = rand(opara.q);
	ox.xH2 = opara.G;
	ox.xH2 *= tmp;

	TMP = ox.xH2;
	TMP *= opara.q;

	ox.xg1 = rand(opara.n);
	ox.ixg1 = inverse(ox.xg1, opara.n);
	
	Hash(msgBYTE, ox.xHm);
	tmp = inverse(sig.s, opara.q);
	ox.xK = mul(tmp*ox.xHm, opara.G, tmp*sig.r, ePK);
	ox.xr = sig.r;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		CommitProve(mip, opara, sig, psk, ox, ow, opi);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of CommitProve = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		NIZKVerf(mip, opara, ePK, ox, opi);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Verf = " << exe_time / num << " ms" << endl;

	if (NIZKVerf(mip, opara, ePK, ox, opi) == 1)
		cout << "Valid!" << endl;
	else
		cout << "Invalid!" << endl;
}