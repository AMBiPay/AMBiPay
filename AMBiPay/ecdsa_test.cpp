#include "ecdsa_test.h"
#include <ctime>
#include<windows.h>
extern miracl *mip;
void ecdsaSetup_test()
{
	Big p, a, b, xG, yG, n;
	ecdsaSysPara sysPara;
	int la = 256;
	BYTE *ecp = (BYTE *) "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
	BYTE *eca = (BYTE *) "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
	BYTE *ecb = (BYTE *) "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
	BYTE *ecxG = (BYTE *) "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
	BYTE *ecyG = (BYTE *) "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
	BYTE *ecn = (BYTE *) "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
	mip->IOBASE = 16;
	p = Big((char *)ecp);
	a = Big((char *)eca);
	b = Big((char *)ecb);
	xG = Big((char *)ecxG);
	yG = Big((char *)ecyG);
	n = Big((char *)ecn);

	if (ecdsaSetup(mip, sysPara, la, p, a, b, xG, yG, n) == 1)
	{
		mip->IOBASE = 16;
		cout << sysPara.p << endl;
		cout << sysPara.a << endl;
		cout << sysPara.b << endl;
		cout << sysPara.n << endl;
		GPrint(sysPara.G);
		cout << "Successful!" << endl;
	}
}

void ecdsaKGen_test()
{
	Big p, a, b, xG, yG, n;
	Big sk;
	ECn PK;
	ecdsaSysPara sysPara;
	int la = 256;
	BYTE *ecp = (BYTE *) "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
	BYTE *eca = (BYTE *) "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
	BYTE *ecb = (BYTE *) "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
	BYTE *ecxG = (BYTE *) "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
	BYTE *ecyG = (BYTE *) "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
	BYTE *ecn = (BYTE *) "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
	mip->IOBASE = 16;
	p = Big((char *)ecp);
	a = Big((char *)eca);
	b = Big((char *)ecb);
	xG = Big((char *)ecxG);
	yG = Big((char *)ecyG);
	n = Big((char *)ecn);
	ecdsaSetup(mip, sysPara, la, p, a, b, xG, yG, n);
	ecdsaKGen(mip, sysPara, sk, PK);
	cout << "sk = " << sk << endl;
	cout << "PK = " << endl;
	GPrint(PK);
}

void ecdsaSign_test()
{
	Big p, a, b, xG, yG, n;
	Big sk;
	ECn PK;
	ecdsaSysPara sysPara;
	int la = 256;
	int msgByteLen;
	ecdsaSig sig;

	BYTE *ecp = (BYTE *) "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
	BYTE *eca = (BYTE *) "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
	BYTE *ecb = (BYTE *) "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
	BYTE *ecxG = (BYTE *) "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
	BYTE *ecyG = (BYTE *) "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
	BYTE *ecn = (BYTE *) "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
	
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
	ecdsaKGen(mip, sysPara, sk, PK);
	if (ecdsaSign(mip, sysPara, sk, msgBYTE, msgByteLen, sig) == 1)
	{
		cout << "r = " << sig.r << endl;
		cout << "s = " << sig.s << endl;
	}
	
}

void ecdsaVerf_test()
{
	LARGE_INTEGER freq;
	LARGE_INTEGER start_t, stop_t;
	double exe_time = 0;

	Big p, a, b, xG, yG, n;
	Big sk;
	ECn PK;
	ecdsaSysPara sysPara;
	int la = 256;
	int msgByteLen;
	ecdsaSig sig;
	int num = 100;

	BYTE *ecp = (BYTE *) "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
	BYTE *eca = (BYTE *) "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
	BYTE *ecb = (BYTE *) "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
	BYTE *ecxG = (BYTE *) "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
	BYTE *ecyG = (BYTE *) "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
	BYTE *ecn = (BYTE *) "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";

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
	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		ecdsaSetup(mip, sysPara, la, p, a, b, xG, yG, n);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of ecdsaSetup = " << exe_time / num << " ms" << endl;
	cout << " sysPara.G = " << sysPara.G << endl;
	QueryPerformanceFrequency(&freq);
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		ecdsaKGen(mip, sysPara, sk, PK);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of ecdsaKGen = " << exe_time / num << " ms" << endl;
	
	QueryPerformanceFrequency(&freq);
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		ecdsaSign(mip, sysPara, sk, msgBYTE, msgByteLen, sig);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of ecdsaSign = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		if (!ecdsaVerf(mip, sysPara, PK, msgBYTE, msgByteLen, sig))
		{
			cout << "Invalid!" << endl;
			break;
		}
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of ecdsaVerf = " << exe_time / num << " ms" << endl;

}